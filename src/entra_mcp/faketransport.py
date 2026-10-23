"""HTTP mock for the no-tenant test layers (A and B). Records every request; fails loudly on anything but GET.

Routing: the fixture maps a key to a response. Keys are matched against the request URL in this order:
exact URL, then "startswith" prefixes under "prefix", then a default 404. A fixture entry is
{"status": 200, "headers": {...}, "body": {...}}.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .graph import Response


class NonGetAttempted(AssertionError):
    pass


@dataclass
class FakeTransport:
    exact: dict[str, dict] = field(default_factory=dict)
    prefix: dict[str, dict] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)
    headers_seen: list[dict] = field(default_factory=list)
    bodies: list[dict | None] = field(default_factory=list)
    allow_writes: bool = False          # the read-path suites keep this False: any non-GET fails the suite
    # optional script: list of (status, body) returned in order for a given prefix (for 429/503 retry tests)
    scripted: dict[str, list[dict]] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str) -> "FakeTransport":
        with open(path) as f:
            d = json.load(f)
        return cls(exact=d.get("exact", {}), prefix=d.get("prefix", {}))

    def __call__(self, method: str, url: str, headers: dict[str, str], timeout: float,
                 body: dict | None = None) -> Response:
        self.requests.append((method, url))
        self.headers_seen.append(dict(headers))
        self.bodies.append(body)
        if method != "GET" and not self.allow_writes:
            raise NonGetAttempted(f"non-GET request attempted: {method} {url}")
        key = f"{method} {url}" if method != "GET" else url
        r = self.exact.get(key)
        if r is None and method != "GET":
            for pfx, resp in self.prefix.items():
                if key.startswith(pfx):
                    r = resp
                    break
            if r is None:
                return Response(404, {"request-id": "fake-404"},
                                {"error": {"code": "Request_ResourceNotFound", "message": "fake: no write route"}})
            return Response(r.get("status", 200), {"request-id": "fake-req"} | r.get("headers", {}), r.get("body", {}))
        for pfx, script in self.scripted.items():
            if url.startswith(pfx) and script:
                r = script.pop(0)
                return Response(r.get("status", 200), r.get("headers", {}), r.get("body", {}))
        r = self.exact.get(url)
        if r is None:
            for pfx, resp in self.prefix.items():
                if url.startswith(pfx):
                    r = resp
                    break
        if r is None:
            return Response(404, {"request-id": "fake-404"},
                            {"error": {"code": "Request_ResourceNotFound", "message": "fake: no route"}})
        return Response(r.get("status", 200), {"request-id": "fake-req"} | r.get("headers", {}), r.get("body", {}))

    def urls(self) -> list[str]:
        return [u for _, u in self.requests]
