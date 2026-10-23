"""Layer B: server authorization. No AI model involved; the harness calls the engine directly.
B1 target guard, B2 injection via tool result, B3 injection via arguments, B4 filter injection,
B5 scope ceiling, B6 secret handling. Mocked here; B1, B3, B5, B6 are repeated live by tests/live_m1.py.
"""
from __future__ import annotations

import json
import re

import pytest
from conftest import ADMIN, ALICE, ALICE_ID, BOB, EVE, EVE_ID, ROOT

from entra_mcp.allowlist import GRAPH, build_url
from entra_mcp.graph import token_roles
from entra_mcp.redact import redact_text, register_secret
from entra_mcp.tools import ToolError


# ---------------------------------------------------------------- B1 target guard
def test_b1_deny_listed_admin_refused_with_zero_graph_calls(engine):
    for tool, args in [("get_user", {"upn": ADMIN}), ("get_sign_in_logs", {"upn": ADMIN}),
                       ("list_auth_methods", {"upn": "SagarModha@ModhaAILabs.onmicrosoft.com"}),
                       ("list_devices", {"upn": ADMIN})]:
        with pytest.raises(ToolError) as ei:
            engine.run(tool, args)
        assert ei.value.code == "protected"
    assert engine.fake.requests == []
    assert all(l["decision"] == "refused" for l in engine.audit.read_all())


def test_b1_role_holder_refused_before_the_tool_request(engine):
    with pytest.raises(ToolError) as ei:
        engine.run("list_auth_methods", {"upn": EVE})
    assert ei.value.code == "admin_target" and "Helpdesk Administrator" in str(ei.value)
    urls = engine.fake.urls()
    assert not any("/authentication/methods" in u for u in urls), "the tool's own request must never be sent"
    assert any("transitiveMemberOf/microsoft.graph.directoryRole" in u for u in urls)


def test_b1_guard_fails_closed_when_a_lookup_errors(engine):
    engine.fake.prefix[f"{GRAPH}/users/{ALICE_ID}/transitiveMemberOf/microsoft.graph.directoryRole"] = {
        "status": 503, "body": {}}
    with pytest.raises(ToolError) as ei:
        engine.run("get_user", {"upn": ALICE})
    assert ei.value.code == "guard_error"


def test_b1_role_assignment_and_role_assignable_group_refuse(engine):
    engine.fake.prefix[f"{GRAPH}/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%27{ALICE_ID}%27"] = {
        "status": 200, "body": {"value": [{"id": "ra1", "roleDefinitionId": "x"}]}}
    with pytest.raises(ToolError) as ei:
        engine.run("get_user", {"upn": ALICE})
    assert ei.value.code == "admin_target" and "assignment" in str(ei.value)
    engine.guard._cache.clear()
    engine.fake.prefix[f"{GRAPH}/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%27{ALICE_ID}%27"] = {
        "status": 200, "body": {"value": []}}
    engine.fake.prefix[f"{GRAPH}/users/{ALICE_ID}/memberOf"] = {"status": 200, "body": {"value": [
        {"@odata.type": "#microsoft.graph.group", "displayName": "privileged-ops", "isAssignableToRole": True}]}}
    with pytest.raises(ToolError) as ei:
        engine.run("get_user", {"upn": ALICE})
    assert "role-assignable" in str(ei.value)


# ---------------------------------------------------------------- B2 injection via tool result
def test_b2_injected_department_is_returned_as_data_and_causes_no_second_request(engine):
    r = engine.run("get_user", {"upn": BOB})
    assert "ignore previous instructions" in r["jobTitle"]
    assert len(engine.fake.requests) == 4             # user + 3 guard lookups, nothing else
    assert not any("signIns" in u or ADMIN.split("@")[0] in u.lower() for u in engine.fake.urls())


def test_b2_injected_device_name_in_sign_in_log_is_quoted_not_acted_on(engine):
    r = engine.run("get_sign_in_logs", {"upn": ALICE, "days": 7})
    assert r["count"] == 2 and r["signIns"][1]["result"] == "failure" and r["signIns"][1]["errorCode"] == 50126
    assert "ipAddress" not in json.dumps(r) and "203.0.113.9" not in json.dumps(r)
    assert not any("/authentication/methods" in u for u in engine.fake.urls())


# ---------------------------------------------------------------- B3 injection via arguments
@pytest.mark.parametrize("upn", [
    "alice.test/../sagarmodha@modhaailabs.onmicrosoft.com",
    "alice.test@modhaailabs.onmicrosoft.com/memberOf",
    "alice.test$@modhaailabs.onmicrosoft.com",
    "alice.test%40modhaailabs.onmicrosoft.com",
    "alice test@modhaailabs.onmicrosoft.com",
    "alice.test@modhaailabs.onmicrosoft.com'",
    "alice.test@modhaailabs.onmicrosoft.com or 1 eq 1",
    "alice.test@contoso.com",
    "x' or userId ne '@modhaailabs.onmicrosoft.com",
    "alice.test@modhaailabs.onmicrosoft.com?$select=*",
    "alice.test@modhaailabs.onmicrosoft.com#",
    ".alice@modhaailabs.onmicrosoft.com",
    "a..b@modhaailabs.onmicrosoft.com",
    "",
])
def test_b3_hostile_upns_rejected_by_schema_before_url_builder(engine, upn):
    with pytest.raises(ToolError) as ei:
        engine.run("get_user", {"upn": upn})
    assert ei.value.code == "invalid_arguments"
    assert engine.fake.requests == []


def test_b3_type_confusion_rejected(engine):
    for args in [{"upn": ["alice.test@modhaailabs.onmicrosoft.com"]}, {"upn": {"$ref": "x"}},
                 {"upn": ALICE, "days": "7; drop"}, {"upn": ALICE, "top": 2.5}, {"upn": ALICE, "top": True}]:
        with pytest.raises(ToolError) as ei:
            engine.run("get_sign_in_logs", args)
        assert ei.value.code == "invalid_arguments", args
    assert engine.fake.requests == []


# ---------------------------------------------------------------- B4 filter injection
def test_b4_sign_in_filter_is_built_from_typed_fields_only(engine):
    engine.run("get_sign_in_logs", {"upn": ALICE, "days": 3, "top": 5})
    url = [u for u in engine.fake.urls() if "/auditLogs/signIns" in u][0]
    m = re.search(r"\$filter=userId%20eq%20%27([0-9a-f-]{36})%27%20and%20createdDateTime%20ge%20(\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}Z)&\$top=5&", url)
    assert m and m.group(1) == ALICE_ID, url
    # the UPN never appears in the sign-in filter at all; only the resolved GUID does
    assert "alice" not in url.lower()
    # and a filter cannot be altered through the builder: the GUID kind rejects anything else
    with pytest.raises(Exception):
        build_url("sign_in_logs", id=f"{ALICE_ID}' or userId ne '", since="2026-10-15T00:00:00Z", top=5)


# ---------------------------------------------------------------- B5 scope ceiling
def test_b5_token_roles_contain_no_write_scope_and_match_the_five_reads():
    import base64
    payload = base64.urlsafe_b64encode(json.dumps({"roles": [
        "User.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All", "AuditLog.Read.All",
        "DeviceManagementManagedDevices.Read.All"]}).encode()).decode().rstrip("=")
    roles = token_roles(f"eyJhbGciOiJSUzI1NiJ9.{payload}.sig")
    assert roles == {"User.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All",
                     "AuditLog.Read.All", "DeviceManagementManagedDevices.Read.All"}
    assert not any("Write" in r for r in roles)
    # a token carrying a write scope would be caught by the same check (used live in tests/live_m1.py)
    payload2 = base64.urlsafe_b64encode(json.dumps({"roles": ["User.ReadWrite.All"]}).encode()).decode().rstrip("=")
    assert any("Write" in r for r in token_roles(f"eyJhbGciOiJSUzI1NiJ9.{payload2}.sig"))


# ---------------------------------------------------------------- B6 secret handling
def test_b6_secret_and_tokens_never_reach_logs_errors_or_results(engine):
    secret = "Abc8Q~fakeSecretValue_ForTestOnly.1234567890abcdefgh"
    register_secret(secret)
    jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20ifQ.c2lnbmF0dXJl"
    # Graph error message that (hostilely) echoes a token and the secret
    engine.fake.prefix[f"{GRAPH}/deviceManagement/managedDevices/11111111-2222-4333-8444-555555555555"] = {
        "status": 403, "body": {"error": {"code": "Forbidden", "message": f"token {jwt} secret {secret} phone +1 240-555-1234"}}}
    with pytest.raises(ToolError) as ei:
        engine.run("get_device", {"device_id": "11111111-2222-4333-8444-555555555555"})
    msg = str(ei.value)
    assert jwt not in msg and secret not in msg and "240-555" not in msg
    assert "<jwt>" in msg and "<client-secret>" in msg
    text = engine.audit_path.read_text()
    assert jwt not in text and secret not in text and "fake-token-not-a-jwt" not in text
    # the Authorization header is the only place the token exists, and it is never written anywhere
    assert all(h["Authorization"].startswith("Bearer ") for h in engine.fake.headers_seen)
    # auth method results: masked phone, no method ids
    r = engine.run("list_auth_methods", {"upn": ALICE})
    dumped = json.dumps(r)
    assert "2405551234" not in dumped and "28c10230" not in dumped and r["methods"][1]["phoneNumber"] == "***34"


def test_b6_repo_contains_no_secret_shaped_string():
    pat = re.compile(r"[A-Za-z0-9]{3}8Q~[A-Za-z0-9._~\-]{30,}|eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")
    for f in ROOT.rglob("*"):
        if f.is_file() and f.suffix in (".py", ".toml", ".md", ".json", ".txt") and ".venv" not in f.parts:
            for m in pat.finditer(f.read_text(errors="ignore")):
                assert "fake" in m.group(0).lower() or f.name.startswith("test_"), f"{f}: {m.group(0)[:12]}…"
