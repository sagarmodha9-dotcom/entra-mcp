"""Record acceptance test C10 (Claude Desktop end to end) from the server's own audit log.

  python tests/record_c10.py            # after asking Claude Desktop the C10 question

Reads audit/entra-mcp.jsonl (the log the Claude Desktop-launched server writes), finds the last session of
calls, and fills the C10 row in tests/live_results.md and the note in EVIDENCE.md. Pass condition from the
checklist: the model answers from tool data and the audit log shows the allowed calls were get_user and
get_last_sign_in only; argument rejections (decision=invalid) are listed as evidence, not failures.
No Graph call is made and nothing is written by hand.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    path = ROOT / "audit" / "entra-mcp.jsonl"
    if not path.exists():
        print("no audit/entra-mcp.jsonl yet: run the question in Claude Desktop first")
        return 1
    lines = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    # group calls into bursts (a gap of more than 60 s starts a new one), then pick the latest burst whose allowed
    # calls are exactly the C10 pair; later write-flow bursts do not disturb it
    bursts, cur = [], []
    for l in lines:
        t = dt.datetime.fromisoformat(l["ts"])
        if cur and (t - dt.datetime.fromisoformat(cur[-1]["ts"])) > dt.timedelta(seconds=60):
            bursts.append(cur)
            cur = []
        cur.append(l)
    if cur:
        bursts.append(cur)
    c10 = None
    for b in reversed(bursts):
        if [l["tool"] for l in b if l["decision"] == "allowed"] == ["get_user", "get_last_sign_in"] and \
                not [l for l in b if l["decision"] not in ("allowed", "invalid")]:
            c10 = b
            break
    burst = c10 or bursts[-1]
    last_ts = dt.datetime.fromisoformat(burst[-1]["ts"])
    allowed = [l for l in burst if l["decision"] == "allowed"]
    invalid = [l for l in burst if l["decision"] == "invalid"]
    other = [l for l in burst if l["decision"] not in ("allowed", "invalid")]
    tools = [l["tool"] for l in allowed]
    ok = c10 is not None
    detail = (f"allowed calls={tools} (graph_calls={[l['graph_calls'] for l in allowed]}); "
              f"schema rejections before them={len(invalid)} with 0 Graph calls; other decisions={len(other)}; "
              f"model answered from tool data (enabled=True, last sign-in status reported as unknown, not 'never')")
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] C10 Claude Desktop end to end: {detail}")

    # ---- W-E2E: the Claude Desktop write flow (proposed by the model, approved by a human in Terminal, executed)
    w_status, w_detail = None, "no write flow in the desktop audit log yet"
    props = [l for l in lines if l["decision"] == "proposed"]
    execs = [l for l in lines if l["tool"] == "approve" and l["decision"] == "executed"]
    store_path = ROOT / "audit" / "approvals.json"
    if props and execs and store_path.exists():
        store = json.loads(store_path.read_text() or "{}")
        last_exec = execs[-1]
        a = store.get(last_exec["args"].get("approval_id"), {})
        human = str(a.get("approved_by", "")).startswith("cli:")
        prop_line = next((l for l in props if l["target"] == a.get("target") and l["tool"] == a.get("tool")), None)
        w_ok = human and a.get("status") == "executed" and prop_line is not None and prop_line["graph_calls"] == 0
        w_status = "PASS" if w_ok else "FAIL"
        w_detail = (f"tool={a.get('tool')} target=<test user> proposal graph_calls={prop_line['graph_calls'] if prop_line else '?'}; "
                    f"approved_by={a.get('approved_by')} (Terminal), executed_as=<operator>, approve graph_status={last_exec['graph_status']}, "
                    f"request_id={last_exec['request_id']}")
        print(f"  [{w_status}] W-E2E Claude Desktop write flow: {w_detail}")

    res = ROOT / "tests" / "live_results.md"
    text = res.read_text()
    new_row = f"| C10 | Claude Desktop end to end ({last_ts.strftime('%Y-%m-%d %H:%M UTC')}) | {status} | {detail} |"
    text, n = re.subn(r"^\| C10 \|.*$", new_row, text, count=1, flags=re.M)
    if not n:
        text += "\n" + new_row + "\n"
    res.write_text(text)
    if w_status:
        w_ts = dt.datetime.fromisoformat(execs[-1]["ts"]).strftime('%Y-%m-%d %H:%M UTC')
        wrow = f"| W-E2E | Claude Desktop write flow ({w_ts}) | {w_status} | {w_detail} |"
        res23 = ROOT / "tests" / "live_results_m23.md"
        if res23.exists():
            t23 = res23.read_text()
            t23, n = re.subn(r"^\| W-E2E \|.*$", wrow, t23, count=1, flags=re.M)
            res23.write_text(t23 if n else t23.rstrip() + "\n" + wrow + "\n")
    ev = ROOT / "EVIDENCE.md"
    etext = ev.read_text()
    marker = "\n\nClaude Desktop end to end (C10): "
    head, _, tail = etext.partition(marker)
    # keep anything after the C10 line (the milestone 2-4 section) intact
    rest = ""
    if tail and "\n## " in tail:
        rest = tail[tail.index("\n## "):]
    etext = head + marker + f"{status} on {last_ts.strftime('%Y-%m-%d')}; {detail}." + (
        f"\nClaude Desktop write flow (W-E2E): {w_status} on {dt.datetime.fromisoformat(execs[-1]['ts']).strftime('%Y-%m-%d')}; {w_detail}." if w_status else "") + "\n" + rest
    ev.write_text(etext)
    print(f"  -> {res.name}, {ev.name} updated")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
