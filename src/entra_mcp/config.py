"""config.toml loader. Secrets are never part of the config (see keychain.py)."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    tenant_id: str
    client_id: str
    domain: str
    keychain_service: str
    keychain_account: str
    protected_upns: frozenset[str]
    guard_cache_seconds: int
    test_device_ids: frozenset[str]
    timeout_seconds: float
    page_size: int
    max_retries: int
    audit_path: Path
    writes_client_id: str = ""                    # second app registration (delegated); empty = write path off
    token_cache_path: Path = Path.home() / "Library/Application Support/entra-mcp/msal_cache.bin"
    approvals_path: Path = Path("audit/approvals.json")
    approval_ttl_seconds: int = 600
    root: Path = field(default_factory=Path.cwd)


def find_config(explicit: str | None = None) -> Path:
    for candidate in (explicit, os.environ.get("ENTRA_MCP_CONFIG"), "config.toml",
                      Path(__file__).resolve().parents[2] / "config.toml"):
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise FileNotFoundError("config.toml not found (pass --config or set ENTRA_MCP_CONFIG)")


def load_config(path: str | Path | None = None) -> Config:
    p = find_config(str(path) if path else None)
    with open(p, "rb") as f:
        raw = tomllib.load(f)
    t, k, g, d, lim, a, w = (raw.get(s, {}) for s in ("tenant", "keychain", "guard", "devices", "limits", "audit", "writes"))
    for key in ("tenant_id", "client_id", "domain"):
        if not t.get(key):
            raise ValueError(f"config [tenant].{key} missing")
    for forbidden in ("client_secret", "secret", "password", "access_token", "refresh_token", "bearer"):
        if any(forbidden in str(key).lower() or forbidden in str(val).lower()[:12] for section in raw.values()
               if isinstance(section, dict) for key, val in section.items() if isinstance(val, str)):
            raise ValueError(f"config contains a '{forbidden}' key: secrets belong in the Keychain, never in config")
    page = int(lim.get("page_size", 20))
    return Config(
        tenant_id=t["tenant_id"], client_id=t["client_id"], domain=t["domain"].lower(),
        keychain_service=k.get("service", "entra-mcp-readonly"), keychain_account=k.get("account", ""),
        protected_upns=frozenset(u.lower() for u in g.get("protected_upns", [])),
        guard_cache_seconds=int(g.get("cache_seconds", 60)),
        test_device_ids=frozenset(d.get("test_device_ids", [])),
        timeout_seconds=float(lim.get("timeout_seconds", 10)), page_size=min(max(page, 1), 50),
        max_retries=int(lim.get("max_retries", 3)),
        audit_path=Path(os.environ.get("ENTRA_MCP_AUDIT") or (p.parent / a.get("path", "audit/entra-mcp.jsonl"))).resolve(),
        writes_client_id=w.get("client_id", ""),
        token_cache_path=Path(os.environ.get("ENTRA_MCP_TOKEN_CACHE") or os.path.expanduser(
            w.get("token_cache", "~/Library/Application Support/entra-mcp/msal_cache.bin"))),
        approvals_path=Path(os.environ.get("ENTRA_MCP_APPROVALS") or (p.parent / w.get("approvals", "audit/approvals.json"))).resolve(),
        approval_ttl_seconds=int(w.get("approval_ttl_seconds", 600)),
        root=p.parent,
    )
