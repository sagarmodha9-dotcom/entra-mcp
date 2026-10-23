"""Layer A: protocol tests. No tenant; Graph is mocked at the HTTP layer (FakeTransport).
A1 handshake over real stdio, A2 schema enforcement, A3 allowlist (exact URL per tool), A4 no generic tool,
A5 GET only, A6 error handling and retries, A7 audit log shape.
"""
from __future__ import annotations

import json
import re
import sys

import pytest
from conftest import ALICE, ALICE_ID, BOB, DEVICE_ID, EVE, ROOT
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from entra_mcp.allowlist import GRAPH, TEMPLATES, TOOL_TEMPLATES, build_url, AllowlistError
from entra_mcp.audit import FIELDS
from entra_mcp.faketransport import NonGetAttempted
from entra_mcp.graph import GraphClient, GraphError, Response
from entra_mcp.schemas import SCHEMAS
from entra_mcp.server import FORBIDDEN_PARAM_NAMES, assert_no_generic_tool, input_schema, tool_definitions
from entra_mcp.tools import ToolError

EXPECTED_TOOLS = ["get_user", "get_last_sign_in", "list_user_groups", "list_auth_methods", "get_sign_in_logs",
                  "list_devices", "get_device"]


# ---------------------------------------------------------------- A1 handshake over stdio
@pytest.mark.asyncio
async def test_a1_handshake_lists_exactly_seven_tools(stdio_env):
    params = StdioServerParameters(command=sys.executable, args=["-m", "entra_mcp"], env=stdio_env, cwd=str(ROOT))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            init = await s.initialize()
            assert init.server_info.name == "entra-mcp"
            listed = await s.list_tools()
            names = [t.name for t in listed.tools]
            assert names == EXPECTED_TOOLS
            for t in listed.tools:
                sch = input_schema(t)
                assert sch["type"] == "object" and sch["additionalProperties"] is False
                assert set(sch["properties"]) == set(SCHEMAS[t.name].model_fields)
            # one real call through the protocol against the mock
            r = await s.call_tool("get_user", {"upn": ALICE})
            body = json.loads(r.content[0].text)
            assert body["accountEnabled"] is True and body["department"] == "IT Support"
            # and a refusal comes back as a structured error result, not a protocol failure
            r = await s.call_tool("get_user", {"upn": "SagarModha@ModhaAILabs.onmicrosoft.com"})
            assert r.is_error and json.loads(r.content[0].text)["error"] == "protected"


# ---------------------------------------------------------------- A2 schema enforcement
@pytest.mark.parametrize("tool,args,needle", [
    ("get_user", {"upn": ALICE, "extra": 1}, "extra"),
    ("get_user", {}, "upn"),
    ("get_sign_in_logs", {"upn": ALICE, "days": 90}, "days"),
    ("get_sign_in_logs", {"upn": ALICE, "top": 500}, "top"),
    ("get_sign_in_logs", {"upn": ALICE, "days": 0}, "days"),
    ("list_devices", {"top": 0}, "top"),
    ("get_device", {"device_id": "not-a-guid"}, "device_id"),
    ("get_device", {"device_id": DEVICE_ID, "path": "/users"}, "path"),
    ("nonexistent_tool", {"upn": ALICE}, "no such tool"),
])
def test_a2_schema_rejections_make_no_graph_call(engine, tool, args, needle):
    with pytest.raises(ToolError) as ei:
        engine.run(tool, args)
    assert ei.value.code in ("invalid_arguments", "unknown_tool")
    assert needle in str(ei.value)
    assert engine.fake.requests == [], "a rejected call must never reach Graph"


# ---------------------------------------------------------------- A3 allowlist: exact URL per tool
def test_a3_every_tool_hits_only_its_allowlisted_urls(engine):
    cases = {
        "get_user": ({"upn": ALICE}, ["user_by_upn", "guard_directory_roles", "guard_role_assignments", "user_member_of"]),
        "get_last_sign_in": ({"upn": ALICE}, ["user_sign_in_activity"]),
        "list_user_groups": ({"upn": ALICE}, []),
        "list_auth_methods": ({"upn": ALICE}, ["user_auth_methods"]),
        "get_sign_in_logs": ({"upn": ALICE, "days": 7, "top": 20}, ["sign_in_logs"]),
        "list_devices": ({"upn": ALICE, "top": 5}, ["managed_devices_by_user"]),
        "get_device": ({"device_id": DEVICE_ID}, ["managed_device"]),
    }
    allowed_prefixes = {name: build_url(name, **{k: v for k, v in {"upn": ALICE, "id": ALICE_ID, "top": 20,
                        "since": "2026-01-01T00:00:00Z", "name": "sg-vpn-users", "mid": ALICE_ID, "gid": ALICE_ID}.items()
                        if k in dict(t.placeholder_kinds)}).split("?")[0]
                        for name, t in TEMPLATES.items()}
    for tool, (args, _) in cases.items():
        engine.fake.requests.clear()
        engine.guard._cache.clear()
        engine.run(tool, args)
        for method, url in engine.fake.requests:
            assert method == "GET"
            assert url.startswith(GRAPH)
            templates_for_tool = set(TOOL_TEMPLATES[tool]) | {"user_by_upn", "guard_directory_roles",
                                                              "guard_role_assignments", "user_member_of"}
            assert any(url.split("?")[0] == allowed_prefixes[t] or url.split("?")[0].startswith(allowed_prefixes[t].rsplit("/", 1)[0] + "/")
                       for t in templates_for_tool), f"{tool} produced a URL outside its allowlist: {url}"
    # exact URLs for the two most sensitive builders
    assert build_url("user_by_upn", upn=ALICE) == f"{GRAPH}/users/alice.test%40modhaailabs.onmicrosoft.com?$select=" + \
        "id,userPrincipalName,displayName,accountEnabled,jobTitle,department,createdDateTime,lastPasswordChangeDateTime,onPremisesSyncEnabled,usageLocation"
    assert build_url("sign_in_logs", id=ALICE_ID, since="2026-10-15T00:00:00Z", top=20).startswith(
        f"{GRAPH}/auditLogs/signIns?$filter=userId%20eq%20%27{ALICE_ID}%27%20and%20createdDateTime%20ge%202026-10-15T00%3A00%3A00Z&$top=20&$select=")


def test_a3_unknown_template_and_bad_placeholders_refused():
    with pytest.raises(AllowlistError):
        build_url("users_list_everything")
    with pytest.raises(AllowlistError):
        build_url("user_sign_in_activity", id="not-a-guid")
    with pytest.raises(AllowlistError):
        build_url("sign_in_logs", id=ALICE_ID, since="2026-10-15", top=20)      # not full ISO
    with pytest.raises(AllowlistError):
        build_url("sign_in_logs", id=ALICE_ID, since="2026-10-15T00:00:00Z", top=51)
    with pytest.raises(AllowlistError):
        build_url("user_by_upn", upn=ALICE, extra="x")                            # unexpected placeholder


# ---------------------------------------------------------------- A4 no generic tool (static)
def test_a4_no_generic_parameter_in_any_tool_and_in_source():
    tools = tool_definitions()
    assert_no_generic_tool(tools)
    for t in tools:
        for pname, prop in input_schema(t)["properties"].items():
            assert pname.lower() not in FORBIDDEN_PARAM_NAMES
            assert "format" not in prop or prop["format"] != "uri"
    # static source check: no function in the package accepts a free-form path/url argument for Graph
    src = (ROOT / "src" / "entra_mcp").glob("*.py")
    for f in src:
        text = f.read_text()
        assert not re.search(r"def \w+\([^)]*\b(url|path|endpoint)\s*:\s*str", text) or f.name in ("faketransport.py", "graph.py", "config.py"), f.name
    # the only place that sends is GraphClient.get with a template name; requests_transport takes the built URL
    graph_src = (ROOT / "src" / "entra_mcp" / "graph.py").read_text()
    assert graph_src.count("build_url(") == 1


# ---------------------------------------------------------------- A5 GET only
def test_a5_transport_fails_on_any_non_get(engine):
    with pytest.raises(NonGetAttempted):
        engine.fake("POST", GRAPH + "/users", {}, 1.0)
    engine.fake.requests.clear()
    # and nothing in the engine's own run produced a non-GET (the fake would have raised)
    engine.run("get_user", {"upn": ALICE})
    assert {m for m, _ in engine.fake.requests} == {"GET"}
    # the client literally has no method other than get
    assert not any(hasattr(GraphClient, m) for m in ("post", "patch", "put", "delete", "request"))


# ---------------------------------------------------------------- A6 error mapping and retries
def _client(cfg, fake):
    return GraphClient(cfg, lambda: "fake", transport=fake, sleep=lambda s: None)


@pytest.mark.parametrize("status,code", [(401, "graph_401"), (403, "graph_403"), (404, "not_found"), (429, "graph_429"), (503, "graph_503")])
def test_a6_each_graph_error_maps_to_a_clear_tool_error(engine, status, code):
    engine.fake.prefix[f"{GRAPH}/deviceManagement/managedDevices/{DEVICE_ID}"] = {
        "status": status, "body": {"error": {"code": "SomeCode", "message": "secret-free message"}}}
    with pytest.raises(ToolError) as ei:
        engine.run("get_device", {"device_id": DEVICE_ID})
    assert ei.value.code == code
    assert str(status) in str(ei.value)
    if status in (429, 503):
        assert len(engine.fake.requests) == 1 + engine.cfg.max_retries, "429/503 must be retried then surfaced"
    else:
        assert len(engine.fake.requests) == 1


def test_a6_retry_then_success(engine):
    key = f"{GRAPH}/deviceManagement/managedDevices/{DEVICE_ID}"
    engine.fake.scripted[key] = [{"status": 429, "headers": {"retry-after": "0"}, "body": {}},
                                 {"status": 503, "body": {}},
                                 {"status": 200, "body": {"id": DEVICE_ID, "deviceName": "test-vm-01", "serialNumber": "X"}}]
    r = engine.run("get_device", {"device_id": DEVICE_ID})
    assert r["deviceName"] == "test-vm-01" and "serialNumber" not in r
    assert len(engine.fake.requests) == 3


# ---------------------------------------------------------------- A7 audit log
def test_a7_every_call_including_refusals_writes_one_line_with_documented_fields(engine):
    engine.run("get_user", {"upn": ALICE})                                 # allowed
    with pytest.raises(ToolError):
        engine.run("get_user", {"upn": ALICE, "bogus": 1})                # invalid
    with pytest.raises(ToolError):
        engine.run("get_user", {"upn": EVE})                              # refused (holds a role)
    with pytest.raises(ToolError):
        engine.run("get_user", {"upn": "nobody.test@modhaailabs.onmicrosoft.com"})   # graph 404
    lines = engine.audit.read_all()
    assert len(lines) == 4
    assert [l["decision"] for l in lines] == ["allowed", "invalid", "refused", "error"]
    for l in lines:
        assert list(l) == list(FIELDS)
        assert l["tool"] == "get_user" and l["ts"].endswith("+00:00")
        assert isinstance(l["latency_ms"], int)
    assert lines[0]["graph_calls"] == 4 and lines[1]["graph_calls"] == 0
    assert lines[2]["error"].startswith("admin_target")
    assert lines[3]["error"].startswith("graph_404")
    assert lines[0]["request_id"] == "fake-req"


def test_a6_timeout_is_retried_then_surfaced_without_crashing(engine):
    from entra_mcp.graph import TransportError
    calls = []

    def dead(method, url, headers, timeout, body=None):
        calls.append(url)
        raise TransportError("ReadTimeout")
    engine.graph._send = dead
    with pytest.raises(ToolError) as ei:
        engine.run("get_device", {"device_id": DEVICE_ID})
    assert ei.value.code == "graph_0" and "timeout" in str(ei.value).lower()
    assert len(calls) == 1 + engine.cfg.max_retries
    assert engine.audit.read_all()[-1]["decision"] == "error"


def test_a6_unexpected_exception_becomes_a_tool_error(engine):
    engine.graph._send = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    with pytest.raises(ToolError) as ei:
        engine.run("get_device", {"device_id": DEVICE_ID})
    assert ei.value.code == "internal" and "boom" not in str(ei.value)


def test_a6_sign_in_logs_have_a_20s_budget_and_one_retry(engine):
    from entra_mcp.graph import TransportError
    seen = []
    real = engine.graph._send

    def slow(method, url, headers, timeout, body=None):
        if "auditLogs/signIns" not in url:            # guard/user lookups answer normally
            return real(method, url, headers, timeout, body)
        seen.append(timeout)
        raise TransportError("ReadTimeout")
    engine.graph._send = slow
    r = engine.run("get_sign_in_logs", {"upn": ALICE, "days": 7})
    assert r["status"] == "unavailable" and "20 s" in r["reason"]
    assert seen == [20.0, 20.0], seen            # two attempts at 20 s each, never the 30 s x 4 default
    assert engine.audit.read_all()[-1]["decision"] == "allowed"   # a clear answer, not a crash
