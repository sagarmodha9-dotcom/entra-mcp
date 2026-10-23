"""Layer W: write path (milestones 2-4), mocked Graph, no tenant.
W1 proposals make no write request; W2 the approve tool cannot execute without a human; W3 human approval then
execution, exact method/URL/body, single use; W4 expiry; W5 admin/deny-list targets; W6 device allowlist and no
wipe/retire anywhere; W7 credential separation (read client cannot send writes, app-only token refused);
W8 generated secrets never persisted; W9 group scope rules; W10 hostile arguments; W11 one template per tool.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import re
from urllib.parse import quote

import pytest
from conftest import ADMIN, ALICE, ALICE_ID, BOB, BOB_ID, CAROL_ID, DEVICE_ID, DOMAIN, EVE, ROOT

from entra_mcp.allowlist import GRAPH, TEMPLATES, WRITE_TEMPLATES, WRITE_TOOL_TEMPLATES, AllowlistError
from entra_mcp.approvals import ApprovalStore
from entra_mcp.audit import AuditLog
from entra_mcp.auth import ensure_delegated
from entra_mcp.faketransport import FakeTransport
from entra_mcp.graph import GraphClient, GraphError, WriteGraphClient
from entra_mcp.tools import ALL_TOOLS, Engine, ToolError
from entra_mcp.writes import DEVICE_WRITES, IDENTITY_WRITES, WriteEngine

CAROL = "carol.test@" + DOMAIN
GROUP_ID = "aaaaaaaa-1111-4222-8333-444444444444"
ROLE_GROUP_ID = "bbbbbbbb-1111-4222-8333-444444444444"
PW_METHOD_ID = "28c10230-6103-485e-b985-444c416c4c52"


def _jwt(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{payload}.c2ln"


DELEGATED = _jwt({"upn": "ops.admin@" + DOMAIN, "oid": "11111111-2222-4333-8444-000000000099",
                  "scp": "User.Read.All User.EnableDisableAccount.All User.RevokeSessions.All "
                         "UserAuthenticationMethod.ReadWrite.All GroupMember.ReadWrite.All Group.Read.All"})
APP_ONLY = _jwt({"roles": ["User.Read.All"], "oid": "x"})


def write_routes(fake: FakeTransport) -> None:
    fake.allow_writes = True
    g = GRAPH
    fake.prefix[f"{g}/groups/{GROUP_ID}"] = {"status": 200, "body": {"id": GROUP_ID, "displayName": "sg-vpn-users",
                                                                     "securityEnabled": True, "isAssignableToRole": False,
                                                                     "mailEnabled": False, "groupTypes": []}}
    fake.prefix[f"{g}/groups?$filter=displayName%20eq%20%27sg-vpn-users%27"] = {"status": 200, "body": {"value": [
        {"id": GROUP_ID, "displayName": "sg-vpn-users", "securityEnabled": True, "isAssignableToRole": False,
         "mailEnabled": False, "groupTypes": []}]}}
    fake.prefix[f"{g}/groups?$filter=displayName%20eq%20%27privileged-ops%27"] = {"status": 200, "body": {"value": [
        {"id": ROLE_GROUP_ID, "displayName": "privileged-ops", "securityEnabled": True, "isAssignableToRole": True,
         "mailEnabled": False, "groupTypes": []}]}}
    fake.prefix[f"{g}/groups?$filter=displayName%20eq%20%27Marketing%20Team%27"] = {"status": 200, "body": {"value": [
        {"id": "cccccccc-1111-4222-8333-444444444444", "displayName": "Marketing Team", "securityEnabled": False,
         "isAssignableToRole": False, "mailEnabled": True, "groupTypes": ["Unified"]}]}}
    for uid in (BOB_ID, CAROL_ID):
        fake.prefix[f"{g}/users/{uid}/authentication/passwordMethods"] = {"status": 200, "body": {"value": [
            {"id": PW_METHOD_ID, "createdDateTime": None}]}}
        fake.prefix[f"PATCH {g}/users/{uid}"] = {"status": 204, "body": ""}
        fake.prefix[f"POST {g}/users/{uid}/revokeSignInSessions"] = {"status": 200, "body": {"value": True}}
        fake.prefix[f"POST {g}/users/{uid}/authentication/methods/{PW_METHOD_ID}/resetPassword"] = {
            "status": 202, "headers": {"location": f"{g}/users/{uid}/authentication/operations/op1"}, "body": ""}
        fake.prefix[f"POST {g}/users/{uid}/authentication/temporaryAccessPassMethods"] = {
            "status": 201, "body": {"id": "tap1", "temporaryAccessPass": "TAPSECRET9876", "lifetimeInMinutes": 60,
                                    "isUsableOnce": True, "startDateTime": "2026-10-22T23:00:00Z"}}
    fake.prefix[f"POST {g}/groups/{GROUP_ID}/members/$ref"] = {"status": 204, "body": ""}
    fake.prefix[f"DELETE {g}/groups/{GROUP_ID}/members/{BOB_ID}/$ref"] = {"status": 204, "body": ""}
    fake.prefix[f"POST {g}/deviceManagement/managedDevices/{DEVICE_ID}/syncDevice"] = {"status": 204, "body": ""}
    fake.prefix[f"POST {g}/deviceManagement/managedDevices/{DEVICE_ID}/rebootNow"] = {"status": 204, "body": ""}


@pytest.fixture
def clock():
    class C:
        t = dt.datetime(2026, 10, 22, 23, 0, tzinfo=dt.timezone.utc)

        def now(self):
            return self.t
    return C()


@pytest.fixture
def wengine(cfg, fake, tmp_path, clock):
    import dataclasses
    from entra_mcp.schemas import set_domain
    cfg = dataclasses.replace(cfg, writes_client_id="22222222-3333-4444-8555-666666666666",
                              test_device_ids=frozenset({DEVICE_ID}))
    set_domain(cfg.domain)
    write_routes(fake)
    read = GraphClient(cfg, lambda: APP_ONLY, transport=fake, sleep=lambda s: None)
    audit = AuditLog(tmp_path / "audit.jsonl")
    engine = Engine(cfg, read, audit)
    store = ApprovalStore(tmp_path / "approvals.json", ttl_seconds=600, now=clock.now)
    token = {"value": DELEGATED}
    engine.writes = WriteEngine(cfg, read, engine.guard, audit, store, lambda: token["value"],
                                write_client_factory=lambda tp: WriteGraphClient(cfg, tp, transport=fake, sleep=lambda s: None))
    engine.writes._sleep = lambda s: None            # static mock: read-back polling must not wait
    engine.fake, engine.store, engine.token, engine.audit_path, engine.clock = fake, store, token, tmp_path / "audit.jsonl", clock
    return engine


def writes_sent(fake):
    return [(m, u) for m, u in fake.requests if m != "GET"]


# ---------------------------------------------------------------- W1 proposals make no write request
@pytest.mark.parametrize("tool,args", [
    ("disable_account", {"upn": BOB, "reason": "INC0001 suspected compromise"}),
    ("enable_account", {"upn": BOB, "reason": "INC0001 cleared"}),
    ("reset_password", {"upn": CAROL, "reason": "INC0002 forgot password"}),
    ("create_temporary_access_pass", {"upn": CAROL, "reason": "INC0003 lost phone", "lifetime_minutes": 60}),
    ("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"}),
    ("add_to_group", {"upn": BOB, "group": "sg-vpn-users", "reason": "REQ0005 vpn access"}),
    ("remove_from_group", {"upn": BOB, "group": GROUP_ID, "reason": "REQ0006 offboard vpn"}),
    ("sync_device", {"device_id": DEVICE_ID, "reason": "INC0007 policy not applied"}),
    ("reboot_device", {"device_id": DEVICE_ID, "reason": "INC0008 stuck update"}),
])
def test_w1_every_write_tool_only_proposes(wengine, tool, args):
    r = wengine.run(tool, args)
    assert r["status"] == "proposed" and r["approval_id"].startswith("apr_") and "Nothing has changed" in r["next_step"]
    assert writes_sent(wengine.fake) == [], "a proposal must never send a write"
    line = wengine.audit.read_all()[-1]
    assert line["decision"] == "proposed" and line["tool"] == tool
    pend = wengine.run("list_pending_approvals", {})
    assert pend["count"] == 1 and pend["pending"][0]["approval_id"] == r["approval_id"]


# ---------------------------------------------------------------- W2 the model cannot approve its own proposal
def test_w2_approve_tool_without_human_approval_is_refused(wengine):
    r = wengine.run("disable_account", {"upn": BOB, "reason": "INC0001 suspected compromise"})
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "not_approved" and "entra-mcp approve" in str(ei.value)
    assert writes_sent(wengine.fake) == []
    assert wengine.store.get(r["approval_id"]).status == "pending"
    assert wengine.audit.read_all()[-1]["decision"] == "refused"


# ---------------------------------------------------------------- W3 human approval, exact request, single use
def test_w3_human_approval_then_execution_exact_request_single_use(wengine):
    r = wengine.run("disable_account", {"upn": BOB, "reason": "INC0001 suspected compromise"})
    aid = r["approval_id"]
    wengine.store.human_approve(aid, "sagar")            # what `entra-mcp approve` does in Terminal
    out = wengine.run("approve", {"approval_id": aid})
    assert out["status"] == "executed" and out["executed_as"] == "ops.admin@" + DOMAIN
    sent = writes_sent(wengine.fake)
    assert sent == [("PATCH", f"{GRAPH}/users/{BOB_ID}")]
    assert wengine.fake.bodies[wengine.fake.requests.index(sent[0])] == {"accountEnabled": False}
    # the write went out with the DELEGATED token, never the app-only one
    hdr = wengine.fake.headers_seen[wengine.fake.requests.index(sent[0])]["Authorization"]
    assert hdr == f"Bearer {DELEGATED}"
    # single use
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": aid})
    assert ei.value.code == "not_executable"
    assert len(writes_sent(wengine.fake)) == 1
    a = wengine.store.get(aid)
    assert a.status == "executed" and a.approved_by == "cli:sagar" and a.executed_as == "ops.admin@" + DOMAIN


@pytest.mark.parametrize("tool,args,method,path,body", [
    ("enable_account", {"upn": BOB, "reason": "INC0001 cleared"}, "PATCH", f"/users/{BOB_ID}", {"accountEnabled": True}),
    ("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"}, "POST", f"/users/{BOB_ID}/revokeSignInSessions", None),
    ("reset_password", {"upn": CAROL_ID and CAROL, "reason": "INC0002 forgot password"}, "POST",
     f"/users/{CAROL_ID}/authentication/methods/{PW_METHOD_ID}/resetPassword", "PASSWORD"),
    ("create_temporary_access_pass", {"upn": CAROL, "reason": "INC0003 lost phone", "lifetime_minutes": 60, "one_time_use": True},
     "POST", f"/users/{CAROL_ID}/authentication/temporaryAccessPassMethods", {"lifetimeInMinutes": 60, "isUsableOnce": True}),
    ("add_to_group", {"upn": BOB, "group": "sg-vpn-users", "reason": "REQ0005 vpn access"}, "POST",
     f"/groups/{GROUP_ID}/members/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{BOB_ID}"}),
    ("remove_from_group", {"upn": BOB, "group": GROUP_ID, "reason": "REQ0006 offboard vpn"}, "DELETE",
     f"/groups/{GROUP_ID}/members/{BOB_ID}/$ref", None),
    ("sync_device", {"device_id": DEVICE_ID, "reason": "INC0007 policy not applied"}, "POST",
     f"/deviceManagement/managedDevices/{DEVICE_ID}/syncDevice", None),
    ("reboot_device", {"device_id": DEVICE_ID, "reason": "INC0008 stuck update"}, "POST",
     f"/deviceManagement/managedDevices/{DEVICE_ID}/rebootNow", None),
])
def test_w3_each_tool_sends_exactly_its_one_template(wengine, tool, args, method, path, body):
    r = wengine.run(tool, args)
    wengine.store.human_approve(r["approval_id"], "sagar")
    out = wengine.run("approve", {"approval_id": r["approval_id"]})
    assert out["status"] == "executed"
    sent = writes_sent(wengine.fake)
    assert sent == [(method, GRAPH + path)], sent
    got = wengine.fake.bodies[wengine.fake.requests.index(sent[0])]
    if body == "PASSWORD":
        assert set(got) == {"newPassword"} and len(got["newPassword"]) >= 20
        assert out["temporaryPassword"] == got["newPassword"] and out["shown_once"] is True
    else:
        assert got == body
    if tool == "create_temporary_access_pass":
        assert out["temporaryAccessPass"] == "TAPSECRET9876"


# ---------------------------------------------------------------- W4 expiry
def test_w4_expired_proposal_cannot_be_approved_or_executed(wengine):
    r = wengine.run("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"})
    wengine.clock.t += dt.timedelta(seconds=601)
    with pytest.raises(Exception) as ei:
        wengine.store.human_approve(r["approval_id"], "sagar")
    assert "expired" in str(ei.value)
    with pytest.raises(ToolError) as ei2:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei2.value.code == "not_executable" and writes_sent(wengine.fake) == []


# ---------------------------------------------------------------- W5 admin targets
def test_w5_deny_listed_and_role_holding_targets_never_get_a_proposal(wengine):
    for upn in (ADMIN, "ops.admin@" + DOMAIN):
        with pytest.raises(ToolError) as ei:
            wengine.run("reset_password", {"upn": upn, "reason": "INC0009 social engineering attempt"})
        assert ei.value.code == "protected"
    assert wengine.fake.requests == []                     # zero Graph calls for deny-listed targets
    with pytest.raises(ToolError) as ei:
        wengine.run("disable_account", {"upn": EVE, "reason": "INC0010 trying to lock out an admin"})
    assert ei.value.code == "admin_target"
    assert wengine.store.pending() == [] and writes_sent(wengine.fake) == []


def test_w5_role_change_between_approval_and_execution_is_caught(wengine):
    r = wengine.run("disable_account", {"upn": BOB, "reason": "INC0001 suspected compromise"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    # Bob becomes an admin in the meantime
    wengine.guard._cache.clear()
    wengine.fake.prefix[f"{GRAPH}/users/{BOB_ID}/transitiveMemberOf/microsoft.graph.directoryRole"] = {
        "status": 200, "body": {"value": [{"id": "r9", "displayName": "User Administrator"}]}}
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "admin_target" and writes_sent(wengine.fake) == []


# ---------------------------------------------------------------- W6 devices and destructive actions
def test_w6_device_not_in_test_list_refused_and_no_wipe_or_retire_anywhere(wengine):
    other = "99999999-2222-4333-8444-555555555555"
    with pytest.raises(ToolError) as ei:
        wengine.run("reboot_device", {"device_id": other, "reason": "INC0011 someone's real laptop"})
    assert ei.value.code == "device_not_allowed" and wengine.fake.requests == []
    for name, t in TEMPLATES.items():
        assert not re.search(r"wipe|retire|/delete|cleanWindowsDevice|resetPasscode|remoteLock", t.path, re.I), name
    assert not any(w in n for n in ALL_TOOLS for w in ("wipe", "retire", "delete", "lock"))
    assert "DELETE" not in {TEMPLATES[t].method for t in WRITE_TEMPLATES if "users" in TEMPLATES[t].path}


# ---------------------------------------------------------------- W7 credential separation
def test_w7_read_client_cannot_send_a_write_template(wengine):
    read = wengine.graph
    for tpl in WRITE_TEMPLATES:
        with pytest.raises(AllowlistError):
            read.get(tpl, id=BOB_ID, gid=GROUP_ID, mid=PW_METHOD_ID) if "gid" in dict(TEMPLATES[tpl].placeholder_kinds) else read.get(tpl, id=BOB_ID, mid=PW_METHOD_ID)
    assert writes_sent(wengine.fake) == []
    # the write client refuses GET templates through write(), and the app-only token is refused outright
    wc = WriteGraphClient(wengine.cfg, lambda: DELEGATED, transport=wengine.fake, sleep=lambda s: None)
    with pytest.raises(AllowlistError):
        wc.write("user_by_upn", None, upn=BOB)
    with pytest.raises(GraphError) as ei:
        ensure_delegated(APP_ONLY)
    assert ei.value.code == "wrong_token_type"


def test_w7_execution_with_app_only_token_is_refused(wengine):
    r = wengine.run("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    wengine.token["value"] = APP_ONLY
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "wrong_token_type" and writes_sent(wengine.fake) == []
    assert wengine.store.get(r["approval_id"]).status == "failed"


# ---------------------------------------------------------------- W8 secrets never persisted
def test_w8_generated_password_and_tap_never_reach_audit_or_approval_store(wengine):
    r1 = wengine.run("reset_password", {"upn": CAROL, "reason": "INC0002 forgot password"})
    r2 = wengine.run("create_temporary_access_pass", {"upn": CAROL, "reason": "INC0003 lost phone"})
    for r in (r1, r2):
        wengine.store.human_approve(r["approval_id"], "sagar")
    o1 = wengine.run("approve", {"approval_id": r1["approval_id"]})
    o2 = wengine.run("approve", {"approval_id": r2["approval_id"]})
    pw, tap = o1["temporaryPassword"], o2["temporaryAccessPass"]
    persisted = wengine.audit_path.read_text() + (wengine.audit_path.parent / "approvals.json").read_text()
    assert pw not in persisted and tap not in persisted and "TAPSECRET" not in persisted
    assert DELEGATED not in persisted and "ops.admin" in persisted      # actor recorded, token not


# ---------------------------------------------------------------- W9 group scope
def test_w9_role_assignable_and_m365_groups_refused_name_resolves_to_id(wengine):
    with pytest.raises(ToolError) as ei:
        wengine.run("add_to_group", {"upn": BOB, "group": "privileged-ops", "reason": "REQ0012 escalate"})
    assert ei.value.code == "admin_target"
    with pytest.raises(ToolError) as ei:
        wengine.run("add_to_group", {"upn": BOB, "group": "Marketing Team", "reason": "REQ0013 teams"})
    assert ei.value.code == "group_out_of_scope"
    r = wengine.run("add_to_group", {"upn": BOB, "group": "sg-vpn-users", "reason": "REQ0005 vpn access"})
    assert GROUP_ID[:8] in r["graph_call"] and wengine.store.get(r["approval_id"]).args["group_id"] == GROUP_ID


# ---------------------------------------------------------------- W10 hostile arguments
@pytest.mark.parametrize("tool,args", [
    ("disable_account", {"upn": BOB}),                                                   # missing reason
    ("disable_account", {"upn": BOB, "reason": "x"}),                                    # too short
    ("disable_account", {"upn": BOB, "reason": "INC0001 <script>alert(1)</script>"}),
    ("disable_account", {"upn": BOB, "reason": "INC0001 ok", "accountEnabled": True}),  # extra field
    ("add_to_group", {"upn": BOB, "group": "sg-vpn-users' or 1 eq 1", "reason": "REQ0005 vpn access"}),
    ("add_to_group", {"upn": BOB, "group": "../groups", "reason": "REQ0005 vpn access"}),
    ("create_temporary_access_pass", {"upn": CAROL, "reason": "INC0003 lost phone", "lifetime_minutes": 10000}),
    ("create_temporary_access_pass", {"upn": CAROL, "reason": "INC0003 lost phone", "one_time_use": "yes"}),
    ("approve", {"approval_id": "apr_zzzz"}),
    ("approve", {"approval_id": "../../approvals.json"}),
    ("reboot_device", {"device_id": "all", "reason": "INC0014 reboot everything"}),
    ("sync_device", {"device_id": DEVICE_ID, "reason": "INC0007 policy", "path": "/wipe"}),
])
def test_w10_hostile_write_arguments_rejected_with_zero_graph_calls(wengine, tool, args):
    with pytest.raises(ToolError) as ei:
        wengine.run(tool, args)
    assert ei.value.code == "invalid_arguments"
    assert wengine.fake.requests == [] and wengine.store.pending() == []


# ---------------------------------------------------------------- W11 one template per tool
def test_w11_each_write_tool_maps_to_exactly_one_non_get_template():
    assert set(WRITE_TOOL_TEMPLATES) == set(IDENTITY_WRITES) | set(DEVICE_WRITES)
    for tool, tpl in WRITE_TOOL_TEMPLATES.items():
        assert TEMPLATES[tpl].method in ("POST", "PATCH", "DELETE"), tool
    assert len(ALL_TOOLS) == 18


# ---------------------------------------------------------------- W12 races, replays, tampering, failures (no live writes)
def test_w12_concurrent_approve_calls_execute_exactly_once(wengine):
    import threading
    r = wengine.run("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    results, errors = [], []

    def go():
        try:
            results.append(wengine.run("approve", {"approval_id": r["approval_id"]}))
        except ToolError as e:
            errors.append(e.code)
    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 1 and len(errors) == 7 and set(errors) == {"not_executable"}
    assert len(writes_sent(wengine.fake)) == 1


def test_w12_two_processes_sharing_the_store_cannot_both_claim(wengine, tmp_path):
    """Simulates a second server process: a separate ApprovalStore instance on the same file."""
    r = wengine.run("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    other = ApprovalStore(wengine.store.path, ttl_seconds=600, now=wengine.clock.now)
    first = other.claim_for_execution(r["approval_id"])        # "other process" wins the claim
    assert first.status == "executed"
    with pytest.raises(ToolError) as ei:                        # our server then cannot execute it
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "not_executable" and writes_sent(wengine.fake) == []
    # and the state survives a "restart" (fresh store instance reads the file)
    assert ApprovalStore(wengine.store.path, now=wengine.clock.now).get(r["approval_id"]).status == "executed"


def test_w12_replay_after_execution_and_cli_reapprove_are_refused(wengine):
    r = wengine.run("disable_account", {"upn": BOB, "reason": "INC0001 suspected compromise"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    wengine.run("approve", {"approval_id": r["approval_id"]})
    for _ in range(3):
        with pytest.raises(ToolError) as ei:
            wengine.run("approve", {"approval_id": r["approval_id"]})
        assert ei.value.code == "not_executable"
    with pytest.raises(Exception) as ei2:                        # the CLI cannot re-arm a spent proposal either
        wengine.store.human_approve(r["approval_id"], "sagar")
    assert "executed" in str(ei2.value)
    assert len(writes_sent(wengine.fake)) == 1
    # denied proposals cannot be approved later
    r2 = wengine.run("disable_account", {"upn": BOB, "reason": "INC0001 suspected compromise"})
    wengine.store.deny(r2["approval_id"], "sagar")
    with pytest.raises(Exception):
        wengine.store.human_approve(r2["approval_id"], "sagar")
    with pytest.raises(ToolError) as ei3:
        wengine.run("approve", {"approval_id": r2["approval_id"]})
    assert ei3.value.code == "not_executable"


def test_w12_tampered_proposal_is_refused_and_denied(wengine):
    r = wengine.run("add_to_group", {"upn": BOB, "group": "sg-vpn-users", "reason": "REQ0005 vpn access"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    # someone edits the approved proposal on disk to point at a different group
    data = json.loads(wengine.store.path.read_text())
    data[r["approval_id"]]["args"]["group_id"] = ROLE_GROUP_ID
    wengine.store.path.write_text(json.dumps(data))
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "tampered" and writes_sent(wengine.fake) == []
    assert wengine.store.get(r["approval_id"]).status == "denied"


def test_w12_graph_error_marks_failed_and_never_retries(wengine):
    r = wengine.run("create_temporary_access_pass", {"upn": CAROL, "reason": "INC0003 lost phone"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    wengine.fake.prefix[f"POST {GRAPH}/users/{CAROL_ID}/authentication/temporaryAccessPassMethods"] = {
        "status": 503, "body": {"error": {"code": "ServiceUnavailable", "message": "try later"}}}
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "graph_503"
    assert len(writes_sent(wengine.fake)) == 1, "a failed write must not be retried"
    a = wengine.store.get(r["approval_id"])
    assert a.status == "failed" and "503" in a.result_summary
    line = wengine.audit.read_all()[-1]
    assert line["decision"] == "failed" and line["action"] == "create_temporary_access_pass"
    assert line["actor"] == "ops.admin@" + DOMAIN and line["target"].endswith(CAROL)
    with pytest.raises(ToolError) as ei2:                        # spent, even though it failed
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei2.value.code == "not_executable"


def test_w12_timeout_is_uncertain_not_executed_and_not_retried(wengine):
    from entra_mcp.graph import TransportError
    r = wengine.run("reset_password", {"upn": CAROL, "reason": "INC0002 forgot password"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    real = wengine.fake.__call__
    sent = []

    def flaky(method, url, headers, timeout, body=None):
        if method == "POST" and "resetPassword" in url:
            sent.append(url)
            raise TransportError("ReadTimeout")
        return real(method, url, headers, timeout, body)
    wengine.writes._factory = lambda tp: WriteGraphClient(wengine.cfg, tp, transport=flaky, sleep=lambda s: None)
    with pytest.raises(ToolError) as ei:
        wengine.run("approve", {"approval_id": r["approval_id"]})
    assert ei.value.code == "uncertain" and "may or may not" in str(ei.value)
    assert len(sent) == 1, "a write that timed out must be sent exactly once"
    a = wengine.store.get(r["approval_id"])
    assert a.status == "uncertain"
    assert wengine.audit.read_all()[-1]["decision"] == "uncertain"


def test_w12_executed_audit_line_is_self_contained(wengine):
    r = wengine.run("revoke_sessions", {"upn": BOB, "reason": "INC0004 stolen laptop"})
    wengine.store.human_approve(r["approval_id"], "sagar")
    wengine.run("approve", {"approval_id": r["approval_id"]})
    line = wengine.audit.read_all()[-1]
    assert line["tool"] == "approve" and line["decision"] == "executed"
    assert line["action"] == "revoke_sessions" and line["target"] == f"revoke_sessions -> {BOB}"
    assert line["actor"] == "ops.admin@" + DOMAIN and line["graph_status"] == 200 and line["request_id"] == "fake-req"
    assert DELEGATED not in json.dumps(line) and "Bearer" not in json.dumps(line)
    prop = [l for l in wengine.audit.read_all() if l["decision"] == "proposed"][-1]
    assert prop["action"] == "revoke_sessions" and prop["actor"] is None
    # a proposal may make READ calls (target guard) but never a write; the only write in the whole flow is the one above
    assert len(writes_sent(wengine.fake)) == 1
