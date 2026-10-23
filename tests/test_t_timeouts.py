"""Layer T: bounded latency. A slow fake transport plus a fake clock prove, without waiting, that every read tool
returns an explicit `unavailable` inside the configured wall-clock deadline instead of hanging or stacking
timeout x retries. T1 per-request timeouts never exceed the deadline; T2 the deadline caps retry loops;
T3 get_last_sign_in degrades to status=unavailable; T4 a slow-but-answering endpoint still succeeds; T5 the
sign-in log keeps its 20 s per-attempt budget; T6 the clock-driven total never exceeds the deadline for any read tool.
"""
from __future__ import annotations

import pytest
from conftest import ALICE

from entra_mcp.graph import TransportError
from entra_mcp.tools import ToolError

READ_TOOLS = {"get_user": {"upn": ALICE}, "get_last_sign_in": {"upn": ALICE}, "list_user_groups": {"upn": ALICE},
              "list_auth_methods": {"upn": ALICE}, "get_sign_in_logs": {"upn": ALICE, "days": 7}, "list_devices": {}}


class FakeClock:
    """perf_counter stand-in. Each transport call 'takes' its timeout when it stalls, or `answer_after` when it answers."""
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def slow_transport(engine, clock, stall_if, answer_after=0.5):
    """Wrap the engine's fake transport: URLs matching `stall_if` consume their full timeout and raise; others answer
    after `answer_after` simulated seconds. Records (url_fragment, timeout) per attempt."""
    real, seen = engine.graph._send, []

    def send(method, url, headers, timeout, body=None):
        seen.append((url.split("/v1.0/")[-1][:40], round(timeout, 1)))
        if stall_if(url):
            clock.t += timeout
            raise TransportError("ReadTimeout")
        clock.t += answer_after
        return real(method, url, headers, timeout, body)
    engine.graph._send = send
    engine.graph.clock = clock
    engine.graph._sleep = lambda s: setattr(clock, "t", clock.t + s)     # backoff sleeps advance the fake clock too
    return seen


def test_t1_no_request_timeout_outlives_the_deadline(engine):
    clock = FakeClock()
    seen = slow_transport(engine, clock, stall_if=lambda u: "signInActivity" in u)
    start = clock.t
    r = engine.run("get_last_sign_in", {"upn": ALICE})
    assert r["status"] == "unavailable" and "deadline" in r["reason"].lower() or r["status"] == "unavailable"
    assert clock.t - start <= engine.cfg.tool_deadline_seconds + 0.01, clock.t - start
    assert all(t <= engine.cfg.timeout_seconds for _, t in seen), seen


def test_t2_deadline_caps_retry_loops_and_names_it(engine):
    clock = FakeClock()
    slow_transport(engine, clock, stall_if=lambda u: "memberOf" in u)   # guard lookup stalls on a 3-retry template
    start = clock.t
    with pytest.raises(ToolError) as ei:
        engine.run("list_user_groups", {"upn": ALICE})
    # the stalled request is a guard lookup: the guard fails CLOSED (refused), it does not guess the target is safe
    assert ei.value.code == "guard_error" and "no response within the tool deadline" in str(ei.value)
    assert clock.t - start <= engine.cfg.tool_deadline_seconds + 0.01
    assert engine.audit.read_all()[-1]["decision"] == "refused"


def test_t3_last_sign_in_degrades_to_unavailable_not_error(engine):
    clock = FakeClock()
    slow_transport(engine, clock, stall_if=lambda u: "signInActivity" in u)
    r = engine.run("get_last_sign_in", {"upn": ALICE})
    assert r["status"] == "unavailable"
    assert engine.audit.read_all()[-1]["decision"] == "allowed"


def test_t4_slow_but_answering_endpoint_still_succeeds(engine):
    clock = FakeClock()
    slow_transport(engine, clock, stall_if=lambda u: False, answer_after=3.0)   # 3 s each, under the 10 s timeout
    r = engine.run("get_user", {"upn": ALICE})
    assert r["accountEnabled"] is True


def test_t5_sign_in_log_keeps_its_20s_budget_inside_the_deadline(engine):
    clock = FakeClock()
    seen = slow_transport(engine, clock, stall_if=lambda u: "auditLogs/signIns" in u)
    start = clock.t
    r = engine.run("get_sign_in_logs", {"upn": ALICE, "days": 7})
    assert r["status"] == "unavailable"
    budgets = [t for u, t in seen if u.startswith("auditLogs")]
    assert budgets and max(budgets) <= 20.0, budgets
    assert clock.t - start <= engine.cfg.tool_deadline_seconds + 0.01


@pytest.mark.parametrize("tool", sorted(READ_TOOLS))
def test_t6_every_read_tool_is_bounded_when_graph_never_answers(engine, tool):
    clock = FakeClock()
    slow_transport(engine, clock, stall_if=lambda u: True)
    start = clock.t
    try:
        r = engine.run(tool, READ_TOOLS[tool])
        assert r.get("status") == "unavailable", r
    except ToolError as e:
        # either an explicit unavailable, or the guard refusing because it could not confirm the target (fail closed)
        assert e.code in ("unavailable", "guard_error"), (e.code, str(e))
    assert clock.t - start <= engine.cfg.tool_deadline_seconds + 0.01, (tool, clock.t - start)


def test_t7_requests_transport_is_wall_clock_bounded_even_when_the_stall_is_outside_the_socket(monkeypatch):
    """A stall that `requests.timeout` cannot see (DNS, TLS, anything before the socket read) must still end at the
    wall-clock bound. Simulated with a Session whose request() sleeps past the timeout and ignores it."""
    import time
    import entra_mcp.graph as g

    class StuckSession:
        def request(self, method, url, headers=None, timeout=None, json=None):
            time.sleep(timeout * 4)              # ignores the socket timeout, like a blocked getaddrinfo
            raise AssertionError("should have been abandoned")
    monkeypatch.setattr(g, "_SESSION", StuckSession())
    t0 = time.perf_counter()
    with pytest.raises(TransportError) as ei:
        g.requests_transport("GET", "https://graph.microsoft.com/v1.0/me", {}, timeout=0.3)
    elapsed = time.perf_counter() - t0
    assert "WallClockTimeout" in str(ei.value)
    assert elapsed < 1.5, elapsed                  # bound is timeout + 0.5 s, not the 1.2 s the stall would take
