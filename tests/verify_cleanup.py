"""Read-only proof that previously exposed test credentials are dead. No writes.

  python tests/verify_cleanup.py

Checks, via the read app only:
  1. carol.test lastPasswordChangeDateTime is LATER than the last tool-issued reset recorded in audit/approvals.json
     (so the two temporary passwords that were pasted into a chat cannot sign in any more)
  2. carol.test has no Temporary Access Pass method registered (the pasted TAP is deleted or expired)
  3. the read app's Keychain secret is present and is not the first (exposed) secret's length-only signature:
     we can only prove presence + length here; rotation itself was done in the portal
Prints PASS/FAIL per item and appends a dated line to tests/live_results_m23.md.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("ENTRA_MCP_AUDIT", str(ROOT / "audit" / "verify_cleanup.jsonl"))

from entra_mcp.audit import AuditLog  # noqa: E402
from entra_mcp.config import load_config  # noqa: E402
from entra_mcp.graph import GraphClient, msal_token_provider  # noqa: E402
from entra_mcp.keychain import client_secret  # noqa: E402
from entra_mcp.schemas import set_domain  # noqa: E402
from entra_mcp.tools import Engine  # noqa: E402


def main() -> int:
    cfg = load_config(ROOT / "config.toml")
    set_domain(cfg.domain)
    carol = f"carol.test@{cfg.domain}"
    secret = client_secret(cfg.keychain_service, cfg.keychain_account)
    engine = Engine(cfg, GraphClient(cfg, msal_token_provider(cfg, secret)), AuditLog(Path(os.environ["ENTRA_MCP_AUDIT"])))
    rows = []

    # last tool-issued reset time, from the approval store (executed_at of the latest reset_password)
    store = json.loads(cfg.approvals_path.read_text() or "{}") if cfg.approvals_path.exists() else {}
    resets = sorted((a.get("executed_at") or "" for a in store.values()
                     if a.get("tool") == "reset_password" and a.get("status") == "executed"), reverse=True)
    last_tool_reset = resets[0] if resets else None
    u = engine.run("get_user", {"upn": carol})
    changed = u.get("lastPasswordChangeDateTime")
    ok1 = bool(last_tool_reset and changed and dt.datetime.fromisoformat(changed.replace("Z", "+00:00")) >
               dt.datetime.fromisoformat(last_tool_reset) + dt.timedelta(seconds=30))
    rows.append(("X1", "carol.test password changed AFTER the last tool-issued reset (exposed temp passwords dead)", ok1,
                 f"last tool reset {last_tool_reset}; lastPasswordChangeDateTime {changed}"))

    kinds = [m["type"] for m in engine.run("list_auth_methods", {"upn": carol})["methods"]]
    rows.append(("X2", "carol.test has no Temporary Access Pass method (exposed TAP gone)", "temporaryAccessPass" not in kinds,
                 f"methods={kinds}"))

    rows.append(("X3", "read app secret present in Keychain (rotated in portal earlier; length check only)", len(secret) >= 32,
                 f"length={len(secret)}"))

    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = ROOT / "tests" / "live_results_m23.md"
    lines = [f"| {i} | {n} ({today}) | {'PASS' if ok else 'FAIL'} | {d} |" for i, n, ok, d in rows]
    text = out.read_text() if out.exists() else ""
    text = re.sub(r"^\| X[123] \|.*\n?", "", text, flags=re.M).rstrip() + "\n" + "\n".join(lines) + "\n"
    out.write_text(text)
    for i, n, ok, d in rows:
        print(f"  [{'PASS' if ok else 'FAIL'}] {i} {n}: {d}")
    print(f"  -> {out.name} updated")
    return 0 if all(ok for _, _, ok, _ in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
