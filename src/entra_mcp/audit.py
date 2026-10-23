"""Append-only JSONL audit log. One line per tool call, including refusals and validation errors.

Fields: ts, tool, action (for approve: the underlying write tool), target (UPN / device id / approval id), actor
(the delegated operator for executed writes), args (redacted), decision (allowed|proposed|executed|failed|uncertain|
refused|invalid|error), graph_status, graph_calls, latency_ms, request_id, error. Results are never logged;
arguments and errors pass through the redaction filter.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
from pathlib import Path

from .redact import redact

FIELDS = ("ts", "tool", "action", "target", "actor", "args", "decision", "graph_status", "graph_calls", "latency_ms",
          "request_id", "error")


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, **fields) -> dict:
        line = {k: fields.get(k) for k in FIELDS}
        line["ts"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
        line = redact(line)
        data = json.dumps(line, separators=(",", ":"), default=str)
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(data + "\n")
            f.flush()
            os.fsync(f.fileno())
        return line

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
