"""Approval store: "model proposes, a human decides, code executes".

Lifecycle: pending -> approved (by a human in Terminal: entra-mcp approve <id>) -> executed (by the approve MCP
tool) | denied | expired. Single use. Persisted as JSON (mode 0600) so the CLI and the server share state; the
file lives under audit/ and is gitignored. Proposals never contain secrets: generated passwords and TAPs are
created at execution time and returned once.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .redact import redact


class ApprovalError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass
class Approval:
    id: str
    tool: str
    args: dict
    target: str                 # UPN or device id
    summary: str                # human-readable: what Graph call would run
    graph_call: str             # "PATCH /users/{id} {accountEnabled: false}"
    created_at: str
    expires_at: str
    status: str = "pending"     # pending | approved | executed | failed | uncertain | denied | expired
    digest: str = ""            # sha256 over (tool, args, target, graph_call); verified before execution
    approved_by: str = "cli"    # how it was approved (cli), recorded with the OS user name
    approved_at: str | None = None
    executed_at: str | None = None
    executed_as: str | None = None   # delegated-token UPN that ran it
    result_summary: str | None = None
    history: list[str] = field(default_factory=list)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.isoformat(timespec="seconds")


def digest_of(tool: str, args: dict, target: str, graph_call: str) -> str:
    raw = json.dumps({"tool": tool, "args": args, "target": target, "graph_call": graph_call}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path: Path, ttl_seconds: int = 600, now=_now):
        self.path, self.ttl, self._now = Path(path), ttl_seconds, now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()            # in-process
        self._lock_path = self.path.with_suffix(".lock")

    @contextlib.contextmanager
    def _locked(self):
        """In-process lock plus an exclusive fcntl lock on a sidecar file, so two processes (two servers, or the CLI
        and a server) cannot both claim the same proposal. Held across each load-modify-save."""
        with self._lock:
            fd = os.open(str(self._lock_path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    # ---------------------------------------------------------------- persistence
    def _load(self) -> dict[str, Approval]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text() or "{}")
        except json.JSONDecodeError:
            return {}
        out = {}
        for k, v in raw.items():
            out[k] = Approval(**v)
        return out

    def _save(self, items: dict[str, Approval]) -> None:
        data = json.dumps({k: redact(asdict(v)) for k, v in items.items()}, indent=1, default=str)
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)

    def _expire(self, items: dict[str, Approval]) -> None:
        now = self._now()
        for a in items.values():
            if a.status in ("pending", "approved") and dt.datetime.fromisoformat(a.expires_at) < now:
                a.status = "expired"
                a.history.append(f"{_iso(now)} expired")

    # ---------------------------------------------------------------- operations
    def propose(self, tool: str, args: dict, target: str, summary: str, graph_call: str) -> Approval:
        with self._locked():
            items = self._load()
            self._expire(items)
            now = self._now()
            args = redact(args)
            a = Approval(id="apr_" + secrets.token_hex(8), tool=tool, args=args, target=target, summary=summary,
                         graph_call=graph_call, created_at=_iso(now), expires_at=_iso(now + dt.timedelta(seconds=self.ttl)),
                         history=[f"{_iso(now)} proposed"], digest=digest_of(tool, args, target, graph_call))
            items[a.id] = a
            self._save(items)
            return a

    def get(self, approval_id: str) -> Approval:
        with self._locked():
            items = self._load()
            self._expire(items)
            self._save(items)
            if approval_id not in items:
                raise ApprovalError("unknown_approval", f"no proposal {approval_id}")
            return items[approval_id]

    def human_approve(self, approval_id: str, who: str) -> Approval:
        """Called ONLY by the CLI (a human in Terminal). The MCP server never calls this."""
        with self._locked():
            items = self._load()
            self._expire(items)
            a = items.get(approval_id)
            if a is None:
                raise ApprovalError("unknown_approval", f"no proposal {approval_id}")
            if a.status != "pending":
                raise ApprovalError("not_pending", f"proposal {approval_id} is {a.status}")
            a.status, a.approved_by, a.approved_at = "approved", f"cli:{who}", _iso(self._now())
            a.history.append(f"{a.approved_at} approved by {a.approved_by}")
            self._save(items)
            return a

    def deny(self, approval_id: str, who: str) -> Approval:
        with self._locked():
            items = self._load()
            a = items.get(approval_id)
            if a is None:
                raise ApprovalError("unknown_approval", f"no proposal {approval_id}")
            if a.status not in ("pending", "approved"):
                raise ApprovalError("not_pending", f"proposal {approval_id} is {a.status}")
            a.status = "denied"
            a.history.append(f"{_iso(self._now())} denied by cli:{who}")
            self._save(items)
            return a

    def claim_for_execution(self, approval_id: str) -> Approval:
        """Atomically move approved -> executed so a proposal can run at most once. Raises unless human-approved."""
        with self._locked():
            items = self._load()
            self._expire(items)
            a = items.get(approval_id)
            if a is None:
                raise ApprovalError("unknown_approval", f"no proposal {approval_id}")
            if a.status == "pending":
                raise ApprovalError("not_approved", f"proposal {approval_id} is not approved by a human yet. "
                                                    f"A person must run in Terminal: entra-mcp approve {approval_id}")
            if a.status != "approved":
                raise ApprovalError("not_executable", f"proposal {approval_id} is {a.status}; proposals are single use")
            if a.digest != digest_of(a.tool, a.args, a.target, a.graph_call):
                a.status = "denied"
                a.history.append(f"{_iso(self._now())} integrity check failed; denied")
                self._save(items)
                raise ApprovalError("tampered", f"proposal {approval_id} was modified after it was created; refused and denied")
            a.status, a.executed_at = "executed", _iso(self._now())
            a.history.append(f"{a.executed_at} claimed for execution")
            self._save(items)
            return a

    def record_result(self, approval_id: str, executed_as: str | None, summary: str, status: str = "executed") -> None:
        """Final outcome: executed (Graph 2xx), failed (Graph 4xx/5xx or local error), uncertain (no response:
        the write may or may not have happened; verify with a read before doing anything else)."""
        with self._locked():
            items = self._load()
            a = items.get(approval_id)
            if a:
                a.executed_as, a.result_summary, a.status = executed_as, redact(summary), status
                a.history.append(f"{_iso(self._now())} result: {redact(summary)[:120]}")
                self._save(items)

    def pending(self) -> list[Approval]:
        with self._locked():
            items = self._load()
            self._expire(items)
            self._save(items)
            return [a for a in items.values() if a.status in ("pending", "approved")]

    def all(self) -> list[Approval]:
        with self._locked():
            items = self._load()
            self._expire(items)
            return sorted(items.values(), key=lambda a: a.created_at)
