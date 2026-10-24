"""Layer C: milestone-1 acceptance against the REAL tenant, through the same Engine the MCP server runs.

  cd ~/entra-mcp && source .venv/bin/activate
  python tests/live_m1.py                 # C1-C9 + live repeats of B1/B3/B5/B6 + latency p50/p95 over 20 calls per tool

Writes tests/live_results.md and EVIDENCE.md (sanitized: GUIDs truncated, only alice/bob/carol by name, no tokens,
no phone numbers, no IPs, no response bodies beyond the fields named in the pass conditions). Read-only: the
engine has no write path, and the token holds no write scope (checked live here as B5).

C10 (Claude Desktop end to end) is a manual step; this script prints what to do and leaves its row pending.
Device rows (C6, C7) stay pending until a dedicated test device is enrolled; this script never changes that.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("ENTRA_MCP_AUDIT", str(ROOT / "audit" / "live_m1.jsonl"))

from entra_mcp.audit import AuditLog  # noqa: E402
from entra_mcp.config import load_config  # noqa: E402
from entra_mcp.graph import GraphClient, msal_token_provider, token_roles  # noqa: E402
from entra_mcp.keychain import client_secret  # noqa: E402
from entra_mcp.redact import redact_text  # noqa: E402
from entra_mcp.schemas import set_domain  # noqa: E402
from entra_mcp.tools import TOOLS, Engine, ToolError  # noqa: E402

TEST_USERS = ("alice.test", "bob.test", "carol.test")
ROWS: list[tuple[str, str, str, str]] = []       # (id, name, status, detail)
LAT: dict[str, dict] = {}


def short(s: object) -> str:
    s = redact_text(str(s))
    s = re.sub(r"\b([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", r"\1…", s)
    # mask any UPN that is not a fictional test user
    return re.sub(r"\b([A-Za-z0-9._\-]+)@([A-Za-z0-9.\-]+)", lambda m: m.group(0) if m.group(1).lower() in TEST_USERS
                  else f"<masked>@{m.group(2)}", s)


def row(cid: str, name: str, ok: bool | None, detail: str) -> None:
    status = "PENDING" if ok is None else ("PASS" if ok else "FAIL")
    ROWS.append((cid, name, status, short(detail)))
    print(f"  [{status:7s}] {cid} {name}: {short(detail)[:160]}")


def timed(engine: Engine, tool: str, args: dict, n: int = 20) -> tuple[dict | None, ToolError | None]:
    """Run a tool n times through the engine (production caching in effect). Reports cache hits (0 Graph requests)
    separately from network calls, and p50/p95 over the NETWORK calls only."""
    net, hits, result, err = [], 0, None, None
    print(f"  … {tool}: {n} timed calls", end="", flush=True)
    for i in range(n):
        before = engine.graph.calls
        t0 = time.perf_counter()
        try:
            result = engine.run(tool, args)
            err = None
        except ToolError as e:
            err = e
        ms = (time.perf_counter() - t0) * 1000
        if engine.graph.calls == before:
            hits += 1
            print(" cache", end="", flush=True)
        else:
            net.append(ms)
            print(f" {int(ms)}ms{'!' if err else ''}", end="", flush=True)
    print()
    srt = sorted(net)
    LAT[tool] = {"n": n, "cache_hits": hits, "network_calls": len(net),
                 "cold_ms": int(net[0]) if net else None,
                 "p50_ms": int(statistics.median(srt)) if srt else None,
                 "p95_ms": int(srt[max(0, int(round(0.95 * len(srt))) - 1)]) if srt else None,
                 "max_ms": int(srt[-1]) if srt else None,
                 "request_id": engine.graph.last_request_id}
    return result, err


def main() -> int:
    import dataclasses
    cfg = dataclasses.replace(load_config(ROOT / "config.toml"), max_retries=1)   # a Graph hang costs <= 1 min here
    set_domain(cfg.domain)
    domain = cfg.domain
    alice, bob, carol = (f"{u}@{domain}" for u in TEST_USERS)
    secret = client_secret(cfg.keychain_service, cfg.keychain_account)
    tp = msal_token_provider(cfg, secret)
    graph = GraphClient(cfg, tp)
    audit_path = Path(os.environ["ENTRA_MCP_AUDIT"])
    if audit_path.exists():
        audit_path.unlink()
    engine = Engine(cfg, graph, AuditLog(audit_path))
    print(f"tenant {short(cfg.tenant_id)}  app {short(cfg.client_id)}  domain {domain}\n")

    # ---- B5 live: scope ceiling from the real token
    roles = token_roles(tp())
    writes = sorted(r for r in roles if "Write" in r or "ReadWrite" in r)
    row("B5", "scope ceiling: real token holds no write scope", not writes and len(roles) == 5,
        f"roles={sorted(roles)} write_scopes={writes or 'none'}")

    # ---- C1 get_user
    r, e = timed(engine, "get_user", {"upn": alice})
    row("C1", "get_user alice.test", bool(r) and all(k in r for k in ("accountEnabled", "displayName", "department")),
        f"accountEnabled={r.get('accountEnabled') if r else None} department={r.get('department') if r else e}")

    # ---- C2 get_last_sign_in (204 is not proof: the engine cross-checks the list query and reports a status)
    r, e = timed(engine, "get_last_sign_in", {"upn": alice})
    st = r.get("status") if r else "error"
    if st == "known":
        when = r.get("lastSignInDateTime") or r.get("lastNonInteractiveSignInDateTime")
        row("C2", "get_last_sign_in alice.test", True, f"status=known lastSignIn={when} (property documented as up to 24 h late)")
    else:
        row("C2", "get_last_sign_in alice.test", None, f"status={st}: {r.get('reason') if r else e} Microsoft documents "
            "signInActivity as updating up to 24 hours after the sign-in; re-run the next day to close this row.")
    # C2b: a user who has not signed in must come back with an explicit status, never a claim of "never signed in"
    rb = engine.run("get_last_sign_in", {"upn": bob})
    row("C2b", "get_last_sign_in on a user without history returns an explicit status",
        rb.get("status") in ("unknown", "unavailable", "known") and "lastSignInDateTime" not in rb or rb.get("status") == "known",
        f"bob.test -> status={rb.get('status')}")

    # ---- C3 list_user_groups
    r, e = timed(engine, "list_user_groups", {"upn": alice})
    names = sorted(g["displayName"] for g in r["groups"]) if r else []
    row("C3", "list_user_groups alice.test", {"sg-helpdesk-test", "sg-vpn-users"} <= set(names), f"groups={names} (error={e})")

    # ---- C4 list_auth_methods
    r, e = timed(engine, "list_auth_methods", {"upn": alice})
    kinds = [m["type"] for m in r["methods"]] if r else []
    dumped = json.dumps(r or {})
    ok4 = bool(r) and "password" in kinds and not re.search(r"\d{7,}", dumped)
    row("C4", "list_auth_methods alice.test (types only, phone masked)",
        ok4 if "microsoftAuthenticator" in kinds else None,
        f"types={kinds}" + ("" if "microsoftAuthenticator" in kinds else
                            " (Authenticator not registered yet: register it for Alice to close C4; pass condition "
                            "needs password + Authenticator)"))

    # ---- C5 get_sign_in_logs
    r, e = timed(engine, "get_sign_in_logs", {"upn": alice, "days": 7, "top": 20}, n=3)   # slow endpoint
    if r and r.get("status") == "known":
        fails = [s for s in r["signIns"] if s["result"] == "failure"]
        ok5 = r["count"] >= 3 and len(fails) >= 1
        row("C5", "get_sign_in_logs alice.test days=7", ok5 if ok5 else None,
            f"entries={r['count']} failures={len(fails)} errorCodes={[s['errorCode'] for s in fails]}"
            + ("" if ok5 else " (pass needs 3 sign-ins incl. one wrong password; Graph lags minutes)"))
        row("C5b", "sign-in rows carry no IP address", "<ip>" not in json.dumps(r) and "ipAddress" not in json.dumps(r), "checked result JSON")
    else:
        row("C5", "get_sign_in_logs alice.test", False, f"{r.get('status') if r else e}: {r.get('reason') if r else ''}")

    # ---- C6 / C7 devices: pending until a dedicated test device is enrolled (never the everyday Mac)
    r, e = timed(engine, "list_devices", {"top": 20})
    n_dev = r["count"] if r else -1
    row("C6", "list_devices", None if n_dev == 0 else bool(r) and all("complianceState" in d for d in r["devices"]),
        f"endpoint 200, devices={n_dev}" + (" (no dedicated test device enrolled yet; stays pending by design)" if n_dev == 0 else ""))
    if r and n_dev > 0:
        dev = r["devices"][0]
        r7, e7 = timed(engine, "get_device", {"device_id": dev["id"]})
        row("C7", "get_device", bool(r7) and "lastSyncDateTime" in r7, f"lastSync={r7.get('lastSyncDateTime') if r7 else e7}")
    else:
        row("C7", "get_device", None, "pending with C6")
        LAT["get_device"] = {"cold_ms": None, "p50_ms": None, "p95_ms": None, "n": 0, "request_id": ""}

    # ---- C8 unknown user -> not_found
    try:
        engine.run("get_user", {"upn": f"nobody.test@{domain}"})
        row("C8", "unknown user maps to not_found", False, "no error raised")
    except ToolError as ex:
        row("C8", "unknown user maps to not_found", ex.code == "not_found", f"{ex.code}: {ex}")

    # ---- C9 / B1 live: admin target refused by the guard, zero Graph calls
    before = engine.graph.calls
    try:
        engine.run("get_user", {"upn": next(iter(cfg.protected_upns))})
        row("C9", "admin target refused by the guard", False, "no error raised")
    except ToolError as ex:
        last = engine.audit.read_all()[-1]
        row("C9", "admin target refused by the guard (B1 live)", ex.code == "protected" and engine.graph.calls == before
            and last["decision"] == "refused", f"{ex.code}; graph_calls={engine.graph.calls - before}; audit decision={last['decision']}")

    # ---- B3 live: hostile arguments never reach Graph (server-level, independent of what Graph would answer)
    before = engine.graph.calls
    rejected = 0
    hostile = [f"alice.test/../admin@{domain}", f"alice.test@{domain}/memberOf", f"alice.test$@{domain}",
               f"alice.test@{domain}'", "alice.test@contoso.com", f"x' or userId ne '@{domain}", f"alice.test@{domain}?$select=*"]
    for h in hostile:
        try:
            engine.run("get_user", {"upn": h})
        except ToolError as ex:
            rejected += ex.code == "invalid_arguments"
    for tool, args in [("get_sign_in_logs", {"upn": alice, "days": 90}), ("list_devices", {"top": 500}),
                       ("get_user", {"upn": alice, "path": "/users"}), ("graph_request", {"url": "/users"})]:
        try:
            engine.run(tool, args)
        except ToolError as ex:
            rejected += ex.code in ("invalid_arguments", "unknown_tool")
    row("B3", "hostile arguments rejected at the server with zero Graph calls (live)",
        rejected == len(hostile) + 4 and engine.graph.calls == before, f"rejected {rejected}/{len(hostile) + 4}; graph_calls={engine.graph.calls - before}")

    # ---- B6 live: nothing secret in the audit log after a full run
    text = audit_path.read_text()
    leak = bool(re.search(r"eyJ[A-Za-z0-9_\-]{16,}|[A-Za-z0-9]{3}8Q~", text)) or secret in text
    row("B6", "audit log holds no token or secret after the run (live)", not leak,
        f"{len(engine.audit.read_all())} audit lines scanned")
    # ---- bounded latency, measured: the slowest single tool call of this run vs the configured deadline
    worst = max(((t, l.get("max_ms") or 0) for t, l in LAT.items()), key=lambda x: x[1], default=("n/a", 0))
    cap_ms = int(cfg.tool_deadline_seconds * 1000)
    row("C-LAT", f"no tool call exceeded tool_deadline_seconds={cfg.tool_deadline_seconds:g} s (measured)",
        worst[1] <= cap_ms + 500,
        f"slowest call this run: {worst[0]} {worst[1]} ms; per-request timeout {cfg.timeout_seconds:g} s, sign-in log "
        f"20 s/attempt; p50 per tool: " + ", ".join(f"{t} {l.get('p50_ms')}" for t, l in LAT.items() if l.get('p50_ms')))

    # ---- C10 manual
    row("C10", "Claude Desktop end to end", None, "manual: ask Claude Desktop 'Is alice.test enabled and when did she "
        "last sign in?' then paste the last lines of audit/entra-mcp.jsonl; expect exactly two tool calls")

    write_results(cfg, roles, engine)
    # carry forward the Claude Desktop result (C10) from the desktop server's own audit log, if it exists
    if (ROOT / "audit" / "entra-mcp.jsonl").exists():
        import record_c10
        c10_ok = record_c10.main() == 0
        ROWS[:] = [(i, n, ("PASS" if c10_ok else "FAIL") if i == "C10" else st, d if i != "C10" else "recorded from audit/entra-mcp.jsonl by record_c10.py")
                   for i, n, st, d in ROWS]
    failed = [r for r in ROWS if r[2] == "FAIL"]
    pend = [r for r in ROWS if r[2] == "PENDING"]
    print(f"\n{len(ROWS) - len(failed) - len(pend)} passed, {len(failed)} failed, {len(pend)} pending  ->  tests/live_results.md, EVIDENCE.md")
    for r in failed:
        print(f"  FAIL {r[0]} {r[1]}: {r[3]}")
    for r in pend:
        print(f"  PENDING {r[0]} {r[1]}: {r[3][:120]}")
    return 1 if failed else 0


EVIDENCE_META = {
    "get_user": ("GET /users/{upn}?$select=…", "User.Read.All", "Free", "none", "no lockout flag exists in Graph"),
    "get_last_sign_in": ("GET /users/{id}?$select=signInActivity (+ list form cross-check)", "AuditLog.Read.All + User.Read.All",
                         "P1", "none", "property updates up to 24 h late (documented); 204/empty -> status=unknown, never 'never signed in'"),
    "list_user_groups": ("GET /users/{id}/memberOf", "Directory.Read.All", "Free", "none", "direct memberships only"),
    "list_auth_methods": ("GET /users/{id}/authentication/methods", "UserAuthenticationMethod.Read.All", "not stated by MS",
                          "none (app)", "phone masked, ids dropped"),
    "get_sign_in_logs": ("GET /auditLogs/signIns?$filter=userId eq '{id}' and createdDateTime ge …", "AuditLog.Read.All",
                         "P1", "none (app)", "30-day retention; no IPs returned; slow endpoint, 10-19 s per call with occasional stalls; 20 s per-attempt budget, one retry, inside the 40 s tool deadline"),
    "list_devices": ("GET /deviceManagement/managedDevices[?$filter=userPrincipalName eq '{upn}']",
                     "DeviceManagementManagedDevices.Read.All", "Intune", "none (app)", "UPN filter unverified until a device exists"),
    "get_device": ("GET /deviceManagement/managedDevices/{id}", "DeviceManagementManagedDevices.Read.All", "Intune",
                   "none (app)", "pending until a dedicated test device is enrolled"),
}
C_BY_TOOL = {"get_user": "C1", "get_last_sign_in": "C2", "list_user_groups": "C3", "list_auth_methods": "C4",
             "get_sign_in_logs": "C5", "list_devices": "C6", "get_device": "C7"}


def write_results(cfg, roles, engine) -> None:
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = {r[0]: r for r in ROWS}
    md = ["# Milestone 1 acceptance: LIVE tenant results (layer C, plus live repeats of B1/B3/B5/B6)", "",
          f"Run: {today}  ", f"Tenant: <tenant id> (<tenant>.onmicrosoft.com, Microsoft 365 Business Premium trial: Entra ID P1 + Intune)  "   # identifiers stay out of committed evidence,
          f"App: <read app id> entra-mcp-readonly, client credentials, roles: {', '.join(sorted(roles))}  ",
          "Path exercised: the same Engine the MCP server runs (schemas -> gate -> allowlisted GETs -> audit), without stdio.", "",
          "These are real Microsoft Graph responses. Mocked results live separately in `tests/unit_results.md`.", "",
          "Sanitized by the results writer: GUIDs truncated, only the fictional test users appear by name, no tokens, "
          "no phone numbers, no IP addresses, no response bodies beyond the fields named in each pass condition.", "",
          "| id | test | result | detail |", "|---|---|---|---|"]
    md += [f"| {i} | {n} | {s} | {d.replace('|', '/')} |" for i, n, s, d in ROWS]
    md += ["", "## Latency per tool (20 calls each, 3 for get_sign_in_logs)", "",
           "Tool-level wall time. Cache hits are calls answered from the 60 s target-guard cache with zero Graph "
           "requests; p50/p95/max are over the network calls only.", "",
           "| tool | calls | cache hits | network calls | cold | p50 | p95 | max | Graph request-id (last) |",
           "|---|---|---|---|---|---|---|---|---|"]
    f = lambda v: f"{v} ms" if v is not None else "pending"   # noqa: E731
    for t in TOOLS:
        l = LAT.get(t, {})
        md.append(f"| {t} | {l.get('n', 0)} | {l.get('cache_hits', 0)} | {l.get('network_calls', 0)} | {f(l.get('cold_ms'))} | "
                  f"{f(l.get('p50_ms'))} | {f(l.get('p95_ms'))} | {f(l.get('max_ms'))} | {l.get('request_id') or 'n/a'} |")
    md += ["", "## Graph request latency per endpoint template (every HTTP request this run, retries included)", "",
           "| template | requests | p50 | p95 | max | timeouts | non-2xx |", "|---|---|---|---|---|---|---|"]
    by: dict[str, list] = {}
    for tpl, ms, st in engine.graph.timings:
        by.setdefault(tpl, []).append((ms, st))
    for tpl, rows in by.items():
        mss = sorted(m for m, _ in rows)
        md.append(f"| {tpl} | {len(rows)} | {int(statistics.median(mss))} ms | {mss[max(0, int(round(0.95 * len(mss))) - 1)]} ms | "
                  f"{mss[-1]} ms | {sum(1 for _, st in rows if st == 'timeout')} | "
                  f"{sum(1 for _, st in rows if st != 'timeout' and not (200 <= int(st) < 300))} |")
    md += ["", "## Audit log sample (placeholders)", "", "```"]
    for line in engine.audit.read_all()[:3]:
        line = dict(line)
        line["args"] = {k: ("<upn>" if k == "upn" else v) for k, v in (line.get("args") or {}).items()}
        line["target"] = "<upn>" if line.get("target") else None
        md.append(json.dumps(line))
    md += ["```", ""]
    (ROOT / "tests" / "live_results.md").write_text("\n".join(md) + "\n")

    ev = ["# Evidence matrix: milestone 1 (read-only)", "",
          "Filled only by `tests/live_m1.py` from real Graph calls. 'Supported' is never written by hand.  ",
          f"Last live run: {today}. Mocked test totals are in `tests/unit_results.md` and are not evidence of tenant behaviour.", "",
          "| tool | Graph endpoint | permission (app) | licence | role needed | live result (date) | latency p50 / p95 | limitations |",
          "|---|---|---|---|---|---|---|---|"]
    for t in TOOLS:
        ep, perm, lic, role, lim = EVIDENCE_META[t]
        r = status.get(C_BY_TOOL[t])
        res = {"PASS": "supported", "FAIL": "FAILED", "PENDING": "pending"}[r[2]] if r else "pending"
        l = LAT.get(t, {})
        lat = f"{l.get('p50_ms')} / {l.get('p95_ms')} ms" if l.get("p50_ms") is not None else "pending"
        ev.append(f"| {t} | {ep} | {perm} | {lic} | {role} | {res} ({today[:10]}) | {lat} | {lim} |")
    n_ok = sum(1 for t in TOOLS if status.get(C_BY_TOOL[t], ("", "", ""))[2] == "PASS")
    n_pend = sum(1 for t in TOOLS if status.get(C_BY_TOOL[t], ("", "", "PENDING"))[2] == "PENDING")
    ev.insert(4, "")
    ev.insert(5, f"**Status: {n_ok} of 7 tools live-validated, {n_pend} pending, "
                 f"{7 - n_ok - n_pend} failed.** Not all seven are validated until the device rows pass.")
    ev += ["", "Pending rows are pending because their precondition is not met yet (a sign-in by the test user, an "
           "Authenticator registration, an enrolled dedicated test device), not because the code is missing. "
           "They are closed only by a later run of the same script."]
    tail = ""
    if (ROOT / "EVIDENCE.md").exists():           # keep the milestone 2-4 section written by live_m23.py
        old = (ROOT / "EVIDENCE.md").read_text()
        marker = "\n## Milestones 2-4"
        if marker in old:
            tail = "\n" + old[old.index(marker):].lstrip("\n")
    (ROOT / "EVIDENCE.md").write_text("\n".join(ev) + "\n" + tail)


if __name__ == "__main__":
    sys.exit(main())
