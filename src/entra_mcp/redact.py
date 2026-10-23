"""Redaction filter applied to every audit line, error message and results file.

Scrubs: bearer tokens / JWTs (eyJ...), API keys (sk-...), client-secret-shaped strings, the known secret
values registered at runtime, phone numbers, IPv4/IPv6 addresses. Applied recursively to dicts and lists.
"""
from __future__ import annotations

import re
from typing import Any

_SECRETS: set[str] = set()

_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]*)?"), "<jwt>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{16,}"), "<jwt>"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), "<api-key>"),
    (re.compile(r"\b[A-Za-z0-9]{3}8Q~[A-Za-z0-9._~\-]{30,}"), "<client-secret>"),   # Entra secret shape
    (re.compile(r"(?i)(client_secret|client_assertion|password|refresh_token|access_token)=[^&\s]+"), r"\1=<redacted>"),
    # phone numbers (10+ digits in phone grouping); written so GUIDs and ISO timestamps are not touched
    (re.compile(r"(?<![\w\-:])\+?\(?\d{1,3}\)?[ \-.]?\(?\d{3}\)?[ \-.]?\d{3}[ \-.]?\d{4}(?![\w\-:])"), "<phone>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"), "<ip>"),
]


def register_secret(value: str) -> None:
    if value and len(value) >= 8:
        _SECRETS.add(value)


def redact_text(s: str) -> str:
    for secret in _SECRETS:
        s = s.replace(secret, "<client-secret>")
    for pat, rep in _PATTERNS:
        s = pat.sub(rep, s)
    return s


def redact(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj
