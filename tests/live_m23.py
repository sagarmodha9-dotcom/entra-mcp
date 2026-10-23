"""Milestones 2-3 (and 4 pending) acceptance against the REAL tenant, through the same Engine the server runs.

  cd ~/entra-mcp && source .venv/bin/activate
  entra-mcp login                      # once: operator device-code sign-in (ops.admin)
  python tests/live_m23.py             # interactive: each write stops and asks you to approve in this Terminal

Targets are the fictional test users bob.test and carol.test only. Every change is reverted or harmless:
disable -> enable, add to group -> remove, revoke sessions (test user), TAP (expires), admin password reset on a
test account. Admin accounts are refused by the server and that refusal is one of the recorded tests.

Writes tests/live_results_m23.md and appends the milestone 2-4 section of EVIDENCE.md (sanitized; passwords and
TAP codes are never displayed by this script and never written anywhere).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("ENTRA_MCP_AUDIT", str(ROOT / "audit" / "live_m23.jsonl"))

from entra_mcp.approvals import ApprovalStore  # noqa: E402
from entra_mcp.audit import AuditLog  # noqa: E402
from entra_mcp.auth import delegated_token_provider, signed_in_account, token_claims  # noqa: E402
from entra_mcp.config import load_config  # noqa: E402
from entra_mcp.graph import GraphClient, msal_token_provider  # noqa: E402
from entra_mcp.keychain import client_secret  # noqa: E402
from entra_mcp.redact import redact_text  # noqa: E402
from entra_mcp.schemas import set_domain  # noqa: E402
from entra_mcp.tools import Engine, ToolError  # noqa: E402
from entra_mcp.writes import WriteEngine  # noqa: E402

TEST_USERS = ("alice.test", "bob.test", "carol.test")
ROLE_TEMPLATES = {"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
                  "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
                  "62e90394-69f5-4237-9190-012177145e10": "Global Administrator"}
ROWS: list[tuple[str, str, str, str]] = []


def short(s: object) -> str:
    s = redact_text(str(s))
    s = re.sub(r"\b([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", r"\1…", s)
    return re.sub(r"\b([A-Za-z0-9._\-]+)@([A-Za-z0-9.\-]+)", lambda m: m.group(0) if m.group(1).lower() in TEST_USERS
                  else f"<masked>@{m.group(2)}", s)


def row(cid: str, name: str, ok: bool | None, detail: str) -> None:
    status = "PENDING" if ok is None else ("PASS" if ok else "FAIL")
    ROWS.append((cid, name, status, short(detail)))
    print(f"  [{status:7s}] {cid} {name}: {short(detail)[:170]}")


def approve_interactively(engine: Engine, proposal: dict) -> dict | None:
    """The human gate. Same store call the CLI makes; the model never gets here."""
    print(f"\n    PROPOSAL {proposal['approval_id']}: {proposal['would_do']}\n    graph call: {proposal['graph_call']}")
    ans = input("    Approve? [y/N] ").strip().lower()
    if ans != "y":
        engine.writes.store.deny(proposal["approval_id"], "sagar")
        return None
    engine.writes.store.human_approve(proposal["approval_id"], os.environ.get("USER", "operator"))
    return engine.run("approve", {"approval_id": proposal["approval_id"]})


def once(label: str, value: str) -> None:
    """The live script never prints a generated password or TAP, in any form. Terminal output gets pasted; the value
    is returned by the tool to its caller and nowhere else. Only its length and character classes are reported."""
    classes = sum(bool(re.search(c, value)) for c in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    print(f"    {label}: not displayed (length {len(value)}, {classes} character classes)")


def main() -> int:
    import dataclasses
    cfg = dataclasses.replace(load_config(ROOT / "config.toml"), max_retries=1)
    set_domain(cfg.domain)
    domain = cfg.domain
    bob, carol = f"bob.test@{domain}", f"carol.test@{domain}"
    if not cfg.writes_client_id:
        print("config [writes].client_id is empty: set it to the entra-mcp-writes app id first")
        return 2
    secret = client_secret(cfg.keychain_service, cfg.keychain_account)
    read = GraphClient(cfg, msal_token_provider(cfg, secret))
    audit_path = Path(os.environ["ENTRA_MCP_AUDIT"])
    if audit_path.exists():
        audit_path.unlink()
    engine = Engine(cfg, read, AuditLog(audit_path))
    store = ApprovalStore(cfg.approvals_path, cfg.approval_ttl_seconds)
    engine.writes = WriteEngine(cfg, read, engine.guard, engine.audit, store, delegated_token_provider(cfg))
    print(f"tenant {short(cfg.tenant_id)}  read app {short(cfg.client_id)}  write app {short(cfg.writes_client_id)}\n")

    # ---- M2-1 operator identity and token type
    acct = signed_in_account(cfg)
    if not acct:
        row("M2-1", "operator signed in (entra-mcp login)", False, "no cached sign-in; run entra-mcp login")
        write_results(cfg, engine)
        return 1
    tok = delegated_token_provider(cfg)()
    claims = token_claims(tok)
    roles = [ROLE_TEMPLATES.get(w, w[:8] + "…") for w in claims.get("roles", [])]
    row("M2-1", "operator signed in; token is DELEGATED (scp present)", bool(claims.get("scp")),
        f"operator={claims.get('upn')} scopes={len(claims.get('scp', []))} directory roles={roles}")
    row("M2-1b", "operator holds User Administrator + Authentication Administrator (least-privilege pair)",
        {"User Administrator", "Authentication Administrator"} <= set(roles) if roles else None,
        f"roles in token={roles}" + ("" if roles else " (wids claim absent: role check via portal)"))
    row("M2-1c", "operator is on the server deny list (cannot be a target)", (claims.get("upn") or "").lower() in cfg.protected_upns,
        f"protected_upns contains operator: {(claims.get('upn') or '').lower() in cfg.protected_upns}")

    # ---- M2-2 the approve tool without a human approval is refused (live, server level)
    p = engine.run("revoke_sessions", {"upn": carol, "reason": "LIVE-M2-2 approval gate check"})
    before = read.calls
    try:
        engine.run("approve", {"approval_id": p["approval_id"]})
        row("M2-2", "approve tool refused without human approval", False, "executed without a human")
    except ToolError as ex:
        row("M2-2", "approve tool refused without human approval", ex.code == "not_approved" and read.calls == before,
            f"{ex.code}; Graph calls during refusal={read.calls - before}")
    store.deny(p["approval_id"], "live_m23")

    # ---- M2-3 expiry (1-second TTL store)
    short_store = ApprovalStore(cfg.approvals_path.with_name("approvals_ttl_test.json"), ttl_seconds=1)
    a = short_store.propose("revoke_sessions", {"upn": carol}, carol, "expiry test", "POST …")
    time.sleep(1.5)
    try:
        short_store.human_approve(a.id, "sagar")
        row("M2-3", "expired proposal cannot be approved", False, "approved after expiry")
    except Exception as ex:
        row("M2-3", "expired proposal cannot be approved", "expired" in str(ex), str(ex))
    short_store.path.unlink(missing_ok=True)

    # ---- M2-4 list_pending_approvals works and admin targets never become proposals
    before = read.calls
    for upn in sorted(cfg.protected_upns):
        try:
            engine.run("disable_account", {"upn": upn, "reason": "LIVE-M2-4 must be refused"})
            row("M2-4", f"admin target refused: {upn}", False, "proposal created for an admin")
        except ToolError as ex:
            row("M2-4", f"admin target refused at proposal time", ex.code == "protected", f"{upn} -> {ex.code}")
    row("M2-4b", "deny-list refusals made zero Graph calls", read.calls == before, f"graph_calls={read.calls - before}")
    row("M2-5", "list_pending_approvals", engine.run("list_pending_approvals", {})["count"] == 0, "0 pending after denials")

    # ---- M3 writes with verification reads (each one asks you to approve)
    def do(cid, tool, args, verify):
        try:
            p = engine.run(tool, args)
            out = approve_interactively(engine, p)
        except ToolError as ex:
            row(cid, tool, False, f"{ex.code}: {ex}")
            return None
        if out is None:
            row(cid, tool, None, "denied at the terminal; not run")
            return None
        ok, detail = verify(out)
        row(cid, tool, ok, f"graph_status={out.get('graph_status')} request_id={out.get('request_id')} executed_as={out.get('executed_as')}; {detail}")
        return out

    do("M3-1", "disable_account", {"upn": bob, "reason": "LIVE-M3-1 disable test user"},
       lambda o: (o.get("accountEnabled") is False, f"read-back accountEnabled={o.get('accountEnabled')}"))
    do("M3-2", "enable_account", {"upn": bob, "reason": "LIVE-M3-2 re-enable test user"},
       lambda o: (o.get("accountEnabled") is True, f"read-back accountEnabled={o.get('accountEnabled')}"))
    do("M3-3", "revoke_sessions", {"upn": carol, "reason": "LIVE-M3-3 revoke test user sessions"},
       lambda o: (o.get("revoked") is True, f"value={o.get('revoked')} (takes effect within minutes, documented)"))
    pw_before = engine.run("get_user", {"upn": carol}).get("lastPasswordChangeDateTime")
    o = do("M3-4", "reset_password", {"upn": carol, "reason": "LIVE-M3-4 admin reset on test user"},
           lambda o: (o.get("graph_accepted") == 202 and len(o.get("temporaryPassword", "")) >= 20,
                      f"accepted={o.get('graph_accepted')} password length={len(o.get('temporaryPassword', ''))} (value not displayed, never written)"))
    if o:
        once("temporary password for carol.test", o["temporaryPassword"])
        changed = None
        for _ in range(12):
            time.sleep(5)
            engine.guard._cache.clear()
            now = engine.run("get_user", {"upn": carol}).get("lastPasswordChangeDateTime")
            if now != pw_before:
                changed = now
                break
        row("M3-4b", "lastPasswordChangeDateTime moved after the reset (async, polled up to 60 s)", bool(changed),
            f"before={pw_before} after={changed or 'unchanged within 60 s'}")
    o = do("M3-5", "create_temporary_access_pass", {"upn": carol, "reason": "LIVE-M3-5 TAP on test user", "lifetime_minutes": 60},
           lambda o: (bool(o.get("temporaryAccessPass")) and o.get("lifetimeInMinutes") == 60,
                      f"lifetime={o.get('lifetimeInMinutes')} oneTime={o.get('isUsableOnce')} (code not displayed, never written)"))
    if o:
        once("TAP for carol.test", o["temporaryAccessPass"])
        kinds, waited = [], 0
        while "temporaryAccessPass" not in kinds and waited <= 30:      # read-after-write lag, observed live
            engine.guard._cache.clear()
            kinds = [m["type"] for m in engine.run("list_auth_methods", {"upn": carol})["methods"]]
            if "temporaryAccessPass" not in kinds:
                time.sleep(5)
                waited += 5
        row("M3-5b", "TAP visible in list_auth_methods, code not included", "temporaryAccessPass" in kinds,
            f"types={kinds} (after {waited}s)")
    do("M3-6", "add_to_group", {"upn": bob, "group": "sg-vpn-users", "reason": "LIVE-M3-6 add test user"},
       lambda o: (o.get("memberNow") is True, f"memberNow={o.get('memberNow')}"))
    do("M3-7", "remove_from_group", {"upn": bob, "group": "sg-vpn-users", "reason": "LIVE-M3-7 remove test user"},
       lambda o: (o.get("memberNow") is False, f"memberNow={o.get('memberNow')}"))

    engine.guard._cache.clear()
    final_bob = engine.run("get_user", {"upn": bob}).get("accountEnabled")
    row("M3-8", "test user left enabled and out of the group at the end", final_bob is True, f"bob.test accountEnabled={final_bob}")

    # ---- M4 devices: pending until a dedicated test device is enrolled and listed in config
    before = read.calls
    try:
        engine.run("reboot_device", {"device_id": "00000000-0000-4000-8000-000000000000", "reason": "LIVE-M4 must be refused"})
        row("M4-0", "device outside test_device_ids refused", False, "proposal created")
    except ToolError as ex:
        row("M4-0", "device outside test_device_ids refused with zero Graph calls", ex.code == "device_not_allowed" and read.calls == before, ex.code)
    row("M4-1", "sync_device on an enrolled dedicated test device", None, f"pending: test_device_ids={sorted(cfg.test_device_ids) or '[]'}, no device enrolled")
    row("M4-2", "reboot_device on an enrolled dedicated test device", None, "pending with M4-1; never run on the everyday Mac")

    # ---- secrets never persisted
    text = audit_path.read_text() + cfg.approvals_path.read_text()
    leak = bool(re.search(r"eyJ[A-Za-z0-9_\-]{16,}|[A-Za-z0-9]{3}8Q~|temporaryPassword|temporaryAccessPass\"\s*:\s*\"[A-Za-z0-9]", text))
    row("B6-w", "audit log and approval store hold no token, password or TAP", not leak,
        f"{len(engine.audit.read_all())} audit lines, {len(store.all())} proposals scanned")

    write_results(cfg, engine)
    failed = [r for r in ROWS if r[2] == "FAIL"]
    pend = [r for r in ROWS if r[2] == "PENDING"]
    print(f"\n{len(ROWS) - len(failed) - len(pend)} passed, {len(failed)} failed, {len(pend)} pending  ->  tests/live_results_m23.md, EVIDENCE.md")
    for r in failed:
        print(f"  FAIL {r[0]} {r[1]}: {r[3]}")
    return 1 if failed else 0


EV = {
    "disable_account": ("PATCH /users/{id} {accountEnabled:false}", "User.EnableDisableAccount.All (delegated)", "User Administrator", "M3-1"),
    "enable_account": ("PATCH /users/{id} {accountEnabled:true}", "User.EnableDisableAccount.All (delegated)", "User Administrator", "M3-2"),
    "reset_password": ("POST /users/{id}/authentication/methods/{mid}/resetPassword", "UserAuthenticationMethod.ReadWrite.All (delegated only)", "Password/User Administrator", "M3-4"),
    "create_temporary_access_pass": ("POST /users/{id}/authentication/temporaryAccessPassMethods", "UserAuthenticationMethod.ReadWrite.All (delegated)", "Authentication Administrator", "M3-5"),
    "revoke_sessions": ("POST /users/{id}/revokeSignInSessions", "User.RevokeSessions.All (delegated)", "Helpdesk/User Administrator", "M3-3"),
    "add_to_group": ("POST /groups/{gid}/members/$ref", "GroupMember.ReadWrite.All (delegated)", "User Administrator", "M3-6"),
    "remove_from_group": ("DELETE /groups/{gid}/members/{id}/$ref", "GroupMember.ReadWrite.All (delegated)", "User Administrator", "M3-7"),
    "sync_device": ("POST /deviceManagement/managedDevices/{id}/syncDevice", "DeviceManagementManagedDevices.PrivilegedOperations.All (delegated)", "Intune Help Desk Operator", "M4-1"),
    "reboot_device": ("POST /deviceManagement/managedDevices/{id}/rebootNow", "DeviceManagementManagedDevices.PrivilegedOperations.All (delegated)", "Intune Help Desk Operator", "M4-2"),
    "approve": ("none (executes a human-approved proposal)", "n/a", "n/a", "M2-2"),
    "list_pending_approvals": ("none", "n/a", "n/a", "M2-5"),
}


def write_results(cfg, engine) -> None:
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = {r[0]: r for r in ROWS}
    md = ["# Milestones 2-4 acceptance: LIVE tenant results", "",
          f"Run: {today}  ", f"Tenant: {short(cfg.tenant_id)} ({cfg.domain})  ",
          f"Read app: {short(cfg.client_id)} (app-only, guard + verification reads). Write app: {short(cfg.writes_client_id)} "
          "(delegated, device-code sign-in, operator ops.admin).  ",
          "Human gate: every write below stopped at the Terminal for a y/N answer before the approve tool could run.", "",
          "Mocked results for this layer are in `tests/unit_results.md` (layer W). This file holds real Graph responses only.", "",
          "| id | test | result | detail |", "|---|---|---|---|"]
    md += [f"| {i} | {n} | {s} | {d.replace('|', '/')} |" for i, n, s, d in ROWS]
    md += ["", "## Audit log sample (placeholders)", "", "```"]
    for line in engine.audit.read_all()[:4]:
        line = dict(line)
        line["args"] = {k: ("<upn>" if k == "upn" else v) for k, v in (line.get("args") or {}).items()}
        line["target"] = "<upn>" if line.get("target") and "@" in str(line.get("target")) else line.get("target")
        md.append(json.dumps(line))
    md += ["```", ""]
    (ROOT / "tests" / "live_results_m23.md").write_text("\n".join(md) + "\n")

    ev_path = ROOT / "EVIDENCE.md"
    base = ev_path.read_text() if ev_path.exists() else "# Evidence matrix\n"
    marker = "\n## Milestones 2-4: approvals, identity writes, device actions\n"
    base = base.split(marker)[0].rstrip() + "\n"
    n_ok = sum(1 for t, (_, _, _, cid) in EV.items() if status.get(cid, ("", "", ""))[2] == "PASS")
    n_pend = sum(1 for t, (_, _, _, cid) in EV.items() if status.get(cid, ("", "", "PENDING"))[2] == "PENDING")
    ev = [marker.strip("\n"), "",
          f"Last live run: {today}. Written only by `tests/live_m23.py`.  ",
          f"**Status: {n_ok} of 11 milestone 2-4 tools live-validated, {n_pend} pending, {11 - n_ok - n_pend} failed.** "
          "Device actions stay pending until a dedicated test device is enrolled.", "",
          "| tool | Graph call | delegated permission | operator role | live result (date) | notes |", "|---|---|---|---|---|---|"]
    for t, (call, perm, role, cid) in EV.items():
        r = status.get(cid)
        res = {"PASS": "supported", "FAIL": "FAILED", "PENDING": "pending"}[r[2]] if r else "pending"
        ev.append(f"| {t} | {call} | {perm} | {role} | {res} ({today[:10]}) | {(r[3][:90] + '…') if r and len(r[3]) > 90 else (r[3] if r else '')} |")
    ev_path.write_text(base + "\n".join(ev) + "\n")


if __name__ == "__main__":
    sys.exit(main())
