"""Graph client: app-only token via MSAL, allowlisted GET requests only, bounded retries, clear errors.

The transport is injectable so the protocol and authorization tests run against an HTTP mock that asserts the
exact method and URL of every request. The real transport is `requests`.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from .allowlist import READ_TEMPLATES, TEMPLATES, AllowlistError, build_url
from .config import Config
from .redact import redact_text


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: object          # parsed JSON (dict/list) or raw text


class Transport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str], timeout: float,
                 body: dict | None = None) -> Response: ...


class GraphError(Exception):
    """A Graph failure mapped to a stable, client-facing message. Never carries tokens or raw bodies."""

    def __init__(self, status: int, code: str, message: str, request_id: str = ""):
        self.status, self.code, self.request_id = status, code, request_id
        super().__init__(redact_text(message))


_MESSAGES = {
    401: "Graph rejected the app token (401). Check the client secret in the Keychain and the app registration.",
    403: "Graph refused this request (403). The app's consented permissions do not cover it, or the licence "
         "(Entra ID P1 / Intune) is missing for this feature.",
    404: "Not found (404): no user or device with that identifier in this tenant.",
    429: "Graph is throttling (429); retried with backoff and still throttled. Try again shortly.",
    503: "Graph service unavailable (503); retried with backoff and still unavailable.",
    0: "No response from Graph (timeout or connection error); retried and still failing. The sign-in log endpoint "
       "in particular can take several seconds; try again.",
    -1: "Tool deadline exhausted: Graph did not answer all of this tool's requests within the configured wall-clock "
        "budget (limits.tool_deadline_seconds). The result is unavailable, not wrong; try again or narrow the query.",
}


class TransportError(Exception):
    """Raised by a transport when no HTTP response was obtained (timeout, DNS, connection reset)."""


_POOL = None
_SESSION = None


def _session():
    """One pooled requests.Session: keep-alive connections mean far fewer DNS lookups and TLS handshakes."""
    global _SESSION
    if _SESSION is None:
        import requests
        _SESSION = requests.Session()
    return _SESSION


def requests_transport(method: str, url: str, headers: dict[str, str], timeout: float,
                       body: dict | None = None) -> Response:
    """HTTP transport with a WALL-CLOCK bound. `requests`' timeout covers connect and per-read waits only; a stall in
    DNS resolution (getaddrinfo) or anywhere else outside the socket is not covered and was measured live at ~30 s
    on macOS even with timeout=10. The call therefore runs in a worker thread and is abandoned after `timeout`
    seconds of wall time; the thread finishes on its own later and its result is discarded."""
    import concurrent.futures
    import requests
    global _POOL
    if _POOL is None:
        _POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="graph-http")

    def do():
        return _session().request(method, url, headers=headers, timeout=timeout, json=body)
    fut = _POOL.submit(do)
    try:
        r = fut.result(timeout=timeout + 0.5)
    except concurrent.futures.TimeoutError:
        raise TransportError(f"WallClockTimeout>{timeout:g}s") from None
    except requests.RequestException as e:
        raise TransportError(type(e).__name__) from None
    try:
        body_out = r.json()
    except ValueError:
        body_out = r.text
    return Response(r.status_code, {k.lower(): v for k, v in r.headers.items()}, body_out)


def msal_token_provider(cfg: Config, secret: str) -> Callable[[], str]:
    import msal
    app = msal.ConfidentialClientApplication(cfg.client_id, authority=f"https://login.microsoftonline.com/{cfg.tenant_id}",
                                             client_credential=secret)

    def get() -> str:
        tok = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])   # cached by MSAL
        if "access_token" not in tok:
            raise GraphError(401, "token_error", f"token request failed: {tok.get('error')}: "
                                                 f"{str(tok.get('error_description'))[:200]}")
        return tok["access_token"]
    return get


def token_roles(token: str) -> set[str]:
    """App roles in the token's claims. Decoded locally for the scope-ceiling test; never validates or logs the token."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return set(json.loads(base64.urlsafe_b64decode(payload)).get("roles", []))
    except Exception:
        return set()


class GraphClient:
    def __init__(self, cfg: Config, token_provider: Callable[[], str], transport: Transport = requests_transport,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg, self._token, self._send, self._sleep = cfg, token_provider, transport, sleep
        self.last_request_id = ""
        self.last_status = 0
        self.calls = 0            # every HTTP request, retries included
        self.timings: list[tuple[str, int, int | str]] = []   # (template, ms, http status or "timeout") per request
        self.deadline: float | None = None   # perf_counter() instant set by Engine.run; every request fits inside it
        self.clock = time.perf_counter

    def start_deadline(self, seconds: float) -> None:
        self.deadline = self.clock() + seconds

    def _remaining(self) -> float | None:
        return None if self.deadline is None else self.deadline - self.clock()

    #: templates this client may execute. The read client is constructed with READ_TEMPLATES and physically
    #: cannot send a write template, whatever token it holds.
    allowed: frozenset[str] = READ_TEMPLATES

    #: per-template budgets for endpoints that are known to be slow: (timeout seconds, retries). The sign-in log
    #: query took 9-19 s with occasional 60 s stalls on the trial tenant; 20 s + 1 retry caps the wait at ~40 s
    #: instead of 30 s x 4 and turns a stall into a fast, explicit `unavailable` answer.
    BUDGETS: dict[str, tuple[float, int]] = {"sign_in_logs": (20.0, 1)}

    def get(self, template: str, **values: object) -> object:
        """GET an allowlisted read template. Refuses any template whose method is not GET."""
        if TEMPLATES.get(template) is None or TEMPLATES[template].method != "GET":
            raise AllowlistError(f"{template!r} is not a GET template")
        return self._request(template, None, values)

    def _request(self, template: str, body: dict | None, values: dict) -> object:
        """Build the URL from an allowlisted template and send it with the template's own method."""
        if template not in self.allowed:
            raise AllowlistError(f"this client may not execute template {template!r}")
        method = TEMPLATES[template].method
        timeout, retries = self.BUDGETS.get(template, (self.cfg.timeout_seconds, self.cfg.max_retries))
        retries = min(retries, self.cfg.max_retries)
        url = build_url(template, **values)
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        delay = 1.0
        for attempt in range(retries + 1):
            remaining = self._remaining()
            if remaining is not None:
                if remaining < 1.0:                       # not worth starting a request that cannot finish
                    self.last_status, self.last_request_id = -1, ""
                    raise GraphError(-1, "deadline", _MESSAGES[-1])
                timeout = min(timeout, remaining)          # the per-request timeout never outlives the tool deadline
            self.calls += 1
            t_req = time.perf_counter()
            try:
                resp = self._send(method, url, headers, timeout, body)
                self.timings.append((template, int((time.perf_counter() - t_req) * 1000), resp.status))
            except TransportError as e:
                self.timings.append((template, int((time.perf_counter() - t_req) * 1000), "timeout"))
                self.last_status, self.last_request_id = 0, ""
                rem = self._remaining()
                if attempt < retries and (rem is None or rem > min(delay, 30.0) + 1.0):
                    self._sleep(min(delay, 30.0))
                    delay *= 2
                    continue
                if rem is not None and rem <= min(delay, 30.0) + 1.0:
                    raise GraphError(-1, "deadline", f"{_MESSAGES[-1]} (last error: {e})") from None
                raise GraphError(0, "no_response", f"{_MESSAGES[0]} ({e})") from None
            self.last_status = resp.status
            self.last_request_id = resp.headers.get("request-id", "") or resp.headers.get("client-request-id", "")
            if resp.status in (429, 503) and attempt < retries:
                retry_after = resp.headers.get("retry-after")
                self._sleep(min(float(retry_after) if retry_after else delay, 30.0))
                delay *= 2
                continue
            if 200 <= resp.status < 300:
                out = resp.body if resp.body != "" else {}
                if isinstance(out, dict):
                    out = {**out, "_status": resp.status, "_location": resp.headers.get("location", "")}
                return out
            code, msg = "graph_error", ""
            if isinstance(resp.body, dict) and isinstance(resp.body.get("error"), dict):
                code = str(resp.body["error"].get("code", code))
                msg = str(resp.body["error"].get("message", ""))[:200]
            text = _MESSAGES.get(resp.status, f"Graph returned HTTP {resp.status}.")
            raise GraphError(resp.status, code, f"{text} ({code}{': ' + msg if msg else ''})", self.last_request_id)
        raise GraphError(self.last_status, "retry_exhausted", _MESSAGES.get(self.last_status, "Graph error"),
                         self.last_request_id)


class WriteGraphClient(GraphClient):
    """Delegated-token client for the write path. May execute every allowlisted template, read or write; the
    method always comes from the template. Constructed only by writes.py after a human approval.

    Writes are sent exactly once: no retry on timeout, 429 or 5xx, because resetPassword and TAP creation are not
    idempotent and a retry after an unobserved success would double-apply. A missing response is surfaced as an
    UNCERTAIN outcome for the caller to verify with a read."""
    allowed = frozenset(TEMPLATES)

    def __init__(self, cfg: Config, token_provider: Callable[[], str], transport: Transport = requests_transport,
                 sleep: Callable[[float], None] = time.sleep):
        import dataclasses
        super().__init__(dataclasses.replace(cfg, max_retries=0), token_provider, transport, sleep)

    def write(self, template: str, body: dict | None = None, **values: object) -> object:
        if TEMPLATES.get(template) is None or TEMPLATES[template].method == "GET":
            raise AllowlistError(f"{template!r} is not a write template")
        return self._request(template, body, values)
