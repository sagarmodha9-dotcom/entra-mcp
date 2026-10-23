"""Delegated (signed-in admin) tokens for the write path: MSAL public client + device code flow.

Policy, not API limit: writes run as a named human so Entra's own audit log records who did what. Only
reset_password is delegated-only by API. The interactive step (`entra-mcp login`) happens in Terminal; the MCP
server itself only ever calls acquire_token_silent on the persisted cache and never prompts.

Cache: MSAL SerializableTokenCache written to a file with mode 0600 under the user's Application Support folder
(never inside the repo). The file holds refresh tokens; it is the one secret the write path keeps on disk.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Callable

from .config import Config
from .graph import GraphError
from .redact import register_secret

WRITE_SCOPES = [
    "User.Read.All", "User.EnableDisableAccount.All", "User.RevokeSessions.All",
    "UserAuthenticationMethod.ReadWrite.All", "GroupMember.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All", "DeviceManagementManagedDevices.Read.All",
]


class NotSignedIn(RuntimeError):
    pass


def _cache_path(cfg: Config) -> Path:
    p = cfg.token_cache_path
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_cache(path: Path):
    import msal
    cache = msal.SerializableTokenCache()
    if path.exists():
        try:
            cache.deserialize(path.read_text())
        except Exception:
            pass
    return cache


def _save_cache(path: Path, cache) -> None:
    if cache.has_state_changed:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(cache.serialize())
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _app(cfg: Config, cache):
    import msal
    return msal.PublicClientApplication(cfg.writes_client_id,
                                        authority=f"https://login.microsoftonline.com/{cfg.tenant_id}", token_cache=cache)


def login(cfg: Config, prompt=print) -> dict:
    """Interactive device-code sign-in, run by the human from Terminal. Returns the signed-in account summary."""
    if not cfg.writes_client_id:
        raise NotSignedIn("config [writes].client_id is not set")
    path = _cache_path(cfg)
    cache = _load_cache(path)
    app = _app(cfg, cache)
    flow = app.initiate_device_flow(scopes=WRITE_SCOPES)
    if "user_code" not in flow:
        raise NotSignedIn(f"device flow failed: {flow.get('error_description', flow)}"[:300])
    prompt(flow["message"])                       # "To sign in, use a web browser to open ... and enter the code ..."
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise NotSignedIn(f"sign-in failed: {result.get('error')}: {str(result.get('error_description'))[:200]}")
    _save_cache(path, cache)
    register_secret(result["access_token"])
    claims = result.get("id_token_claims", {})
    return {"account": claims.get("preferred_username"), "name": claims.get("name"),
            "scopes": sorted(result.get("scope", "").split()), "cache": str(path)}


def signed_in_account(cfg: Config) -> dict | None:
    if not cfg.writes_client_id:
        return None
    cache = _load_cache(_cache_path(cfg))
    accounts = _app(cfg, cache).get_accounts()
    return {"username": accounts[0].get("username")} if accounts else None


def delegated_token_provider(cfg: Config) -> Callable[[], str]:
    """Silent-only token provider for the server. Raises NotSignedIn (never prompts) when the cache can't help."""
    path = _cache_path(cfg)

    def get() -> str:
        cache = _load_cache(path)
        app = _app(cfg, cache)
        accounts = app.get_accounts()
        if not accounts:
            raise NotSignedIn("no signed-in operator: run 'entra-mcp login' in Terminal")
        result = app.acquire_token_silent(WRITE_SCOPES, account=accounts[0])
        _save_cache(path, cache)
        if not result or "access_token" not in result:
            raise NotSignedIn("operator sign-in expired: run 'entra-mcp login' in Terminal")
        register_secret(result["access_token"])
        return result["access_token"]
    return get


def token_claims(token: str) -> dict:
    """Unverified local decode, used only to record WHO approved/executed a write (upn, oid) in the audit log."""
    import base64
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        c = json.loads(base64.urlsafe_b64decode(payload))
        return {"upn": c.get("upn") or c.get("preferred_username"), "oid": c.get("oid"),
                "scp": sorted((c.get("scp") or "").split()), "roles": c.get("wids", [])}
    except Exception:
        return {}


def ensure_delegated(token: str) -> None:
    """Fail closed if a token that reaches the write path is not a delegated token (must carry 'scp')."""
    c = token_claims(token)
    if not c.get("scp"):
        raise GraphError(401, "wrong_token_type", "write path received a token without delegated scopes; refusing")
