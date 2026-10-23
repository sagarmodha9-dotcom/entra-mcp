"""Reproducible, SIMULATED demonstration of the entra-mcp workflow.

    python demo/run_demo.py            -> demo/transcript.json (+ printed walkthrough)

Everything here runs against the in-repo FakeTransport (an HTTP mock of Microsoft Graph). There is no network, no
token, no tenant: the tenant id is all zeros, the domain is `contoso-demo.onmicrosoft.com`, every user is fictional,
and every Graph response below is the fixture's canned answer. The code path exercised is the real server code
(schemas, allowlist, target guard, approval store, write engine, audit log); only the transport is fake.

Human approval is simulated by calling the same function the Terminal CLI calls (`ApprovalStore.human_approve`),
and the transcript labels that step as the human's action. The MCP `approve` tool cannot approve anything; the
demo shows it being refused before the human acts.

Device actions (sync/reboot) are NOT demonstrated: they are built and mock-tested but pending a live device, and
this demo does not pretend otherwise.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from entra_mcp.allowlist import GRAPH  # noqa: E402
from entra_mcp.approvals import ApprovalStore  # noqa: E402
from entra_mcp.audit import AuditLog  # noqa: E402
from entra_mcp.config import Config  # noqa: E402
from entra_mcp.faketransport import FakeTransport  # noqa: E402
from entra_mcp.graph import GraphClient, WriteGraphClient  # noqa: E402
from entra_mcp.schemas import set_domain  # noqa: E402
from entra_mcp.tools import Engine, ToolError  # noqa: E402
from entra_mcp.writes import WriteEngine  # noqa: E402

DOMAIN = "contoso-demo.onmicrosoft.com"
ADMIN = "it.admin@" + DOMAIN                  # deny-listed: never a valid target
OPERATOR = "ops.operator@" + DOMAIN           # the human who signs in for writes (fictional)
ALICE, ALICE_ID = "alice.demo@" + DOMAIN, "a1a1a1a1-0000-4000-8000-000000000001"
CAROL, CAROL_ID = "carol.demo@" + DOMAIN, "c3c3c3c3-0000-4000-8000-000000000003"
ZERO_TENANT = "00000000-0000-0000-0000-000000000000"


def _jwt(claims: dict) -> str:
    """A syntactically JWT-shaped string for the fake delegated token. Not signed, not from Microsoft."""
    import base64
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{payload}.ZGVtbw"


def user(upn, uid, dept, job):
    return {"id": uid, "userPrincipalName": upn, "displayName": upn.split("@")[0].replace(".", " ").title(),
            "accountEnabled": True, "jobTitle": job, "department": dept, "createdDateTime": "2026-01-15T09:00:00Z",
            "lastPasswordChangeDateTime": "2026-09-01T12:00:00Z", "onPremisesSyncEnabled": None, "usageLocation": "US"}


def build_fake() -> FakeTransport:
    u = lambda upn: f"{GRAPH}/users/{quote(upn, safe='')}"  # noqa: E731
    empty = {"status": 200, "body": {"value": []}}
    f = FakeTransport(allow_writes=True)
    f.prefix[u(ALICE)] = {"status": 200, "body": user(ALICE, ALICE_ID, "Finance", "Analyst")}
    f.prefix[u(CAROL)] = {"status": 200, "body": user(CAROL, CAROL_ID, "Marketing", "Coordinator")}
    for uid in (ALICE_ID, CAROL_ID):
        f.prefix[f"{GRAPH}/users/{uid}/transitiveMemberOf/microsoft.graph.directoryRole"] = empty
        f.prefix[f"{GRAPH}/users/{uid}/memberOf"] = {"status": 200, "body": {"value": [
            {"@odata.type": "#microsoft.graph.group", "displayName": "sg-all-staff", "securityEnabled": True,
             "isAssignableToRole": False, "groupTypes": []}]}}
        f.prefix[f"{GRAPH}/users/{uid}?$select=id,signInActivity"] = {"status": 200, "body": {
            "id": uid, "signInActivity": {"lastSignInDateTime": "2026-10-21T14:12:09Z",
                                          "lastNonInteractiveSignInDateTime": "2026-10-22T08:01:44Z"}}}
        f.prefix[f"POST {GRAPH}/users/{uid}/revokeSignInSessions"] = {"status": 200, "body": {"value": True}}
    f.prefix[f"{GRAPH}/roleManagement/directory/roleAssignments"] = empty
    return f


class Clock:
    t = dt.datetime(2026, 10, 23, 14, 0, tzinfo=dt.timezone.utc)

    def now(self):
        self.t += dt.timedelta(seconds=7)
        return self.t


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="entra-mcp-demo-"))
    cfg = Config(tenant_id=ZERO_TENANT, client_id=ZERO_TENANT, domain=DOMAIN, keychain_service="demo",
                 keychain_account="demo", protected_upns=frozenset({ADMIN, OPERATOR}), guard_cache_seconds=60,
                 test_device_ids=frozenset(), timeout_seconds=5, page_size=20, max_retries=0,
                 audit_path=tmp / "audit.jsonl", writes_client_id=ZERO_TENANT, approvals_path=tmp / "approvals.json",
                 root=tmp)
    set_domain(cfg.domain)
    fake, clock = build_fake(), Clock()
    read = GraphClient(cfg, lambda: "fake-app-only-token", transport=fake, sleep=lambda s: None)
    audit = AuditLog(cfg.audit_path)
    engine = Engine(cfg, read, audit, now=clock.now)
    store = ApprovalStore(cfg.approvals_path, ttl_seconds=600, now=clock.now)
    delegated = _jwt({"upn": OPERATOR, "oid": "0p0p0p0p-0000-4000-8000-000000000099",
                      "scp": "User.Read.All User.RevokeSessions.All User.EnableDisableAccount.All"})
    engine.writes = WriteEngine(cfg, read, engine.guard, audit, store, lambda: delegated,
                                write_client_factory=lambda tp: WriteGraphClient(cfg, tp, transport=fake, sleep=lambda s: None))
    engine.writes._sleep = lambda s: None

    steps: list[dict] = []

    def call(tool: str, args: dict):
        before = len(fake.requests)
        try:
            out, err = engine.run(tool, args), None
        except ToolError as e:
            out, err = None, {"code": e.code, "message": str(e)}
        sent = fake.requests[before:]
        return out, err, sent

    def step(phase: str, actor: str, title: str, caption: str, tool: str | None = None, args: dict | None = None,
             result=None, error=None, graph=None, human_cmd: str | None = None):
        steps.append({"phase": phase, "actor": actor, "title": title, "caption": caption, "tool": tool, "args": args,
                      "result": result, "error": error, "graph_requests": [f"{m} {u.replace(GRAPH, '')}" for m, u in (graph or [])],
                      "human_command": human_cmd})

    # 0 ------------------------------------------------------------------ framing
    step("intro", "system", "SIMULATED demonstration",
         "Real server code, fake Microsoft Graph transport. Tenant 0000…, domain contoso-demo.onmicrosoft.com, "
         "fictional users. No network, no credentials, no live Microsoft operation.")

    # 1 ------------------------------------------------------------------ read request
    out, err, sent = call("get_user", {"upn": ALICE})
    step("read", "ai", "MCP read: get_user", "The model asks a read-only question. Fixed Graph template, fixed field "
         "allowlist, admin targets refused before any call.", "get_user", {"upn": ALICE}, out, err, sent)

    out, err, sent = call("get_last_sign_in", {"upn": ALICE})
    step("read", "ai", "MCP read: get_last_sign_in", "signInActivity is returned with its documented 24 h lag noted; "
         "when Graph has nothing, the tool says 'unknown', never 'never signed in'.", "get_last_sign_in",
         {"upn": ALICE}, out, err, sent)

    # 2 ------------------------------------------------------------------ input validation
    bad = {"upn": "alice.demo@contoso-demo.onmicrosoft.com' OR 1=1 --", "extra": "field"}
    out, err, sent = call("get_user", bad)
    step("validate", "ai", "Input validation", "Hostile or malformed arguments are rejected by the strict schema "
         "(UPN regex + tenant domain, extra fields forbidden). Zero Graph calls.", "get_user", bad, out, err, sent)

    # 3 ------------------------------------------------------------------ denied unauthorized action
    args = {"upn": ADMIN, "reason": "INC0099 test"}
    out, err, sent = call("disable_account", args)
    step("deny", "ai", "DENIED: write against an admin", "disable_account on a deny-listed admin is refused at "
         "proposal time by the target guard. No proposal is created. Zero Graph calls.", "disable_account", args,
         out, err, sent)

    # 4 ------------------------------------------------------------------ proposal
    args = {"upn": CAROL, "reason": "INC0042 lost laptop, revoke all sessions"}
    out, err, sent = call("revoke_sessions", args)
    approval_id = out["approval_id"]
    step("propose", "ai", "Write tool = proposal only", "revoke_sessions does not touch Graph. It records a proposal "
         "with a SHA-256 digest over (tool, args, target, graph call) and a 10-minute expiry.", "revoke_sessions",
         args, out, err, sent)

    # 5 ------------------------------------------------------------------ AI tries to execute without a human
    out, err, sent = call("approve", {"approval_id": approval_id})
    step("boundary", "ai", "The AI cannot approve its own proposal", "Calling the approve tool on a pending proposal "
         "is refused: status is 'pending', not 'approved'. Only the Terminal CLI can change that.", "approve",
         {"approval_id": approval_id}, out, err, sent)

    # 6 ------------------------------------------------------------------ human approval (simulated, labelled)
    a = store.human_approve(approval_id, "jordan (Terminal)")
    step("human", "human", "HUMAN approval in Terminal (simulated)", "A person reviews the proposal and runs the CLI. "
         "This is the only code path that moves a proposal to 'approved'. The MCP server never calls it.",
         None, None, {"approval_id": a.id, "status": a.status, "approved_by": a.approved_by,
                      "summary": a.summary, "graph_call": a.graph_call}, None, [],
         human_cmd=f"entra-mcp approve {approval_id}")

    # 7 ------------------------------------------------------------------ execution
    out, err, sent = call("approve", {"approval_id": approval_id})
    step("execute", "ai", "Approved execution", "Now the approve tool claims the proposal (digest re-verified), sends "
         "exactly one write with the operator's delegated token, and records the outcome. No automatic retry.",
         "approve", {"approval_id": approval_id}, out, err, sent)

    # 8 ------------------------------------------------------------------ replay
    out, err, sent = call("approve", {"approval_id": approval_id})
    step("replay", "ai", "Replay refused", "The same approval id a second time: the proposal is already 'executed'. "
         "Single use, enforced by the store under a file lock.", "approve", {"approval_id": approval_id}, out, err, sent)

    # 9 ------------------------------------------------------------------ audit trail
    lines = [json.loads(line) for line in cfg.audit_path.read_text().splitlines()]
    keep = ("ts", "tool", "action", "target", "actor", "decision", "graph_status", "graph_calls", "request_id", "error")
    trail = [{k: line.get(k) for k in keep if line.get(k) is not None} for line in lines]
    text = cfg.audit_path.read_text() + cfg.approvals_path.read_text()
    leak = bool(re.search(r"eyJ[A-Za-z0-9_\-]{16,}|fake-app-only-token|8Q~", text))
    step("audit", "system", "Audit trail (redacted JSONL)", "Every call, allowed or refused, is one line: tool, action, "
         "target, actor, decision, Graph status, request id. Tokens and secrets never appear "
         f"(scan of this run's audit + approval files: {'LEAK' if leak else 'clean'}).", None, None, trail, None, [])

    # 10 ----------------------------------------------------------------- not shown
    step("outro", "system", "Not demonstrated: Intune device actions", "sync_device and reboot_device are implemented "
         "and mock-tested, gated on a config allowlist of device ids, and still PENDING a disposable enrolled device. "
         "Nothing in this demo was a live Microsoft Graph result.")

    out_path = ROOT / "demo" / "transcript.json"
    out_path.write_text(json.dumps({"generated_by": "demo/run_demo.py", "simulated": True, "domain": DOMAIN,
                                    "tenant_id": ZERO_TENANT, "steps": steps}, indent=1))
    for i, s in enumerate(steps):
        tag = {"ai": "AI ", "human": "HUMAN", "system": "SYS"}[s["actor"]]
        print(f"[{i:02d}] {tag:5} {s['title']}")
        if s["graph_requests"]:
            print(f"        graph: {s['graph_requests']}")
        if s["error"]:
            print(f"        -> {s['error']['code']}")
    print(f"\n{len(steps)} steps -> {out_path.relative_to(ROOT)}  (leak scan: {'LEAK' if leak else 'clean'})")
    return 1 if leak else 0


if __name__ == "__main__":
    sys.exit(main())
