# Milestones 2-4 acceptance: LIVE tenant results

Run: 2026-10-22 23:55 UTC  
Tenant: 62130626… (modhaailabs.onmicrosoft.com)  
Read app: e3b405e7… (app-only, guard + verification reads). Write app: c2fee14d… (delegated, device-code sign-in, operator ops.admin).  
Human gate: every write below stopped at the Terminal for a y/N answer before the approve tool could run.

Mocked results for this layer are in `tests/unit_results.md` (layer W). This file holds real Graph responses only.

| id | test | result | detail |
|---|---|---|---|
| M2-1 | operator signed in; token is DELEGATED (scp present) | PASS | operator=<masked>@ModhaAILabs.onmicrosoft.com scopes=11 directory roles=['Authentication Administrator', 'User Administrator', 'b79fbf4d…'] |
| M2-1b | operator holds User Administrator + Authentication Administrator (least-privilege pair) | PASS | roles in token=['Authentication Administrator', 'User Administrator', 'b79fbf4d…'] |
| M2-1c | operator is on the server deny list (cannot be a target) | PASS | protected_upns contains operator: True |
| M2-2 | approve tool refused without human approval | PASS | not_approved; Graph calls during refusal=0 |
| M2-3 | expired proposal cannot be approved | PASS | proposal apr_f5bf602fba6383bb is expired |
| M2-4 | admin target refused at proposal time | PASS | <masked>@modhaailabs.onmicrosoft.com -> protected |
| M2-4 | admin target refused at proposal time | PASS | <masked>@modhaailabs.onmicrosoft.com -> protected |
| M2-4b | deny-list refusals made zero Graph calls | PASS | graph_calls=0 |
| M2-5 | list_pending_approvals | PASS | 0 pending after denials |
| M3-1 | disable_account | PASS | graph_status=204 request_id=b3c9e62c… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; read-back accountEnabled=False |
| M3-2 | enable_account | PASS | graph_status=204 request_id=641b6f63… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; read-back accountEnabled=True |
| M3-3 | revoke_sessions | PASS | graph_status=200 request_id=d56f886b… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; value=True (takes effect within minutes, documented) |
| M3-4 | reset_password | PASS | graph_status=202 request_id=d2412ad1… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; accepted=202 password length=20 (value shown once below, never written) |
| M3-4b | lastPasswordChangeDateTime moved after the reset (async, polled up to 60 s) | PASS | before=2026-10-22T23:49:20Z after=2026-10-22T23:54:46Z |
| M3-5 | create_temporary_access_pass | PASS | graph_status=201 request_id=874a030f… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; lifetime=60 oneTime=True (code shown once below, never written) |
| M3-5b | TAP visible in list_auth_methods, code not included | FAIL | types=['password'] |
| M3-6 | add_to_group | PASS | graph_status=204 request_id=f2852f4a… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; memberNow=True |
| M3-7 | remove_from_group | PASS | graph_status=204 request_id=55dba119… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; memberNow=False |
| M3-8 | test user left enabled and out of the group at the end | PASS | bob.test accountEnabled=True |
| M4-0 | device outside test_device_ids refused with zero Graph calls | PASS | device_not_allowed |
| M4-1 | sync_device on an enrolled dedicated test device | PENDING | pending: test_device_ids=[], no device enrolled |
| M4-2 | reboot_device on an enrolled dedicated test device | PENDING | pending with M4-1; never run on the everyday Mac |
| B6-w | audit log and approval store hold no token, password or TAP | PASS | 25 audit lines, 14 proposals scanned |

## Audit log sample (placeholders)

```
{"ts": "2026-10-22T23:54:23.330+00:00", "tool": "revoke_sessions", "args": {"upn": "<upn>", "reason": "LIVE-M2-2 approval gate check"}, "target": "<upn>", "decision": "proposed", "graph_status": 200, "graph_calls": 4, "latency_ms": 843, "request_id": "c93a30c9-809c-4dcc-9c8c-39a683e6d468", "error": null}
{"ts": "2026-10-22T23:54:23.331+00:00", "tool": "approve", "args": {"approval_id": "apr_5470f21c4c9f10f4"}, "target": "apr_5470f21c4c9f10f4", "decision": "refused", "graph_status": 200, "graph_calls": 0, "latency_ms": 0, "request_id": "c93a30c9-809c-4dcc-9c8c-39a683e6d468", "error": "not_approved: proposal apr_5470f21c4c9f10f4 is not approved by a human yet. A person must run in Terminal: entra-mcp approve apr_5470f21c4c9f10f4"}
{"ts": "2026-10-22T23:54:24.840+00:00", "tool": "disable_account", "args": {"upn": "<upn>", "reason": "LIVE-M2-4 must be refused"}, "target": "<upn>", "decision": "refused", "graph_status": 200, "graph_calls": 0, "latency_ms": 0, "request_id": "c93a30c9-809c-4dcc-9c8c-39a683e6d468", "error": "protected: this account is protected by the server's deny list; no tool may target it"}
{"ts": "2026-10-22T23:54:24.842+00:00", "tool": "disable_account", "args": {"upn": "<upn>", "reason": "LIVE-M2-4 must be refused"}, "target": "<upn>", "decision": "refused", "graph_status": 200, "graph_calls": 0, "latency_ms": 0, "request_id": "c93a30c9-809c-4dcc-9c8c-39a683e6d468", "error": "protected: this account is protected by the server's deny list; no tool may target it"}
```
| W-E2E | Claude Desktop write flow (2026-10-22 23:58 UTC) | PASS | tool=revoke_sessions target=<test user> proposal graph_calls=0; approved_by=cli:sagarmodha (Terminal), executed_as=<operator>, approve graph_status=200, request_id=0a6f38de-1136-4a11-aab7-532731a1b09c |
| X1 | carol.test password changed AFTER the last tool-issued reset (exposed temp passwords dead) (2026-10-23 00:36 UTC) | PASS | last tool reset 2026-10-22T23:54:50+00:00; lastPasswordChangeDateTime 2026-10-23T00:32:34Z |
| X2 | carol.test has no Temporary Access Pass method (exposed TAP gone) (2026-10-23 00:36 UTC) | FAIL | methods=['password', 'temporaryAccessPass'] |
| X3 | read app secret present in Keychain (rotated in portal earlier; length check only) (2026-10-23 00:36 UTC) | PASS | length=40 |
