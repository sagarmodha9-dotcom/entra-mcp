# Milestone 1 acceptance: LIVE tenant results (layer C, plus live repeats of B1/B3/B5/B6)

Run: 2026-10-24 16:44 UTC  
Tenant: <tenant id> (<tenant>.onmicrosoft.com, Microsoft 365 Business Premium trial: Entra ID P1 + Intune)  
App: <read app id> entra-mcp-readonly, client credentials, roles: AuditLog.Read.All, DeviceManagementManagedDevices.Read.All, Directory.Read.All, User.Read.All, UserAuthenticationMethod.Read.All  
Path exercised: the same Engine the MCP server runs (schemas -> gate -> allowlisted GETs -> audit), without stdio.

These are real Microsoft Graph responses. Mocked results live separately in `tests/unit_results.md`.

Sanitized by the results writer: GUIDs truncated, only the fictional test users appear by name, no tokens, no phone numbers, no IP addresses, no response bodies beyond the fields named in each pass condition.

| id | test | result | detail |
|---|---|---|---|
| B5 | scope ceiling: real token holds no write scope | PASS | roles=['AuditLog.Read.All', 'DeviceManagementManagedDevices.Read.All', 'Directory.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All'] write_scopes=none |
| C1 | get_user alice.test | PASS | accountEnabled=True department=IT Support |
| C2 | get_last_sign_in alice.test | PASS | status=known lastSignIn=2026-10-22T20:33:35Z (property documented as up to 24 h late) |
| C2b | get_last_sign_in on a user without history returns an explicit status | PASS | bob.test -> status=unknown |
| C3 | list_user_groups alice.test | PASS | groups=['Modha AI Labs', 'sg-helpdesk-test', 'sg-vpn-users'] (error=None) |
| C4 | list_auth_methods alice.test (types only, phone masked) | PASS | types=['password', 'microsoftAuthenticator'] |
| C5 | get_sign_in_logs alice.test days=7 | PASS | entries=12 failures=6 errorCodes=[50140, 50126, 50140, 50140, 50126, 50140] |
| C5b | sign-in rows carry no IP address | PASS | checked result JSON |
| C6 | list_devices | PENDING | endpoint 200, devices=0 (no dedicated test device enrolled yet; stays pending by design) |
| C7 | get_device | PENDING | pending with C6 |
| C8 | unknown user maps to not_found | PASS | not_found: Not found (404): no user or device with that identifier in this tenant. (Request_ResourceNotFound: Resource '<masked>@<tenant>.onmicrosoft.com' does not exist or one of its queried reference-property objects are not present.) |
| C9 | admin target refused by the guard (B1 live) | PASS | protected; graph_calls=0; audit decision=refused |
| B3 | hostile arguments rejected at the server with zero Graph calls (live) | PASS | rejected 11/11; graph_calls=0 |
| B6 | audit log holds no token or secret after the run (live) | PASS | 117 audit lines scanned |
| C-LAT | no tool call exceeded tool_deadline_seconds=40 s (measured) | PASS | slowest call this run: get_last_sign_in 30105 ms; per-request timeout 10 s, sign-in log 20 s/attempt; p50 per tool: get_user 640, get_last_sign_in 405, list_user_groups 515, list_auth_methods 344, get_sign_in_logs 1195, list_devices 110 |
| C10 | Claude Desktop end to end (2026-10-22 20:39 UTC) | PASS | allowed calls=['get_user', 'get_last_sign_in'] (graph_calls=[4, 2]); schema rejections before them=2 with 0 Graph calls; other decisions=0; model answered from tool data (enabled=True, last sign-in status reported as unknown, not 'never') |

## Latency per tool (20 calls each, 3 for get_sign_in_logs)

Tool-level wall time. Cache hits are calls answered from the 60 s target-guard cache with zero Graph requests; p50/p95/max are over the network calls only.

| tool | calls | cache hits | network calls | cold | p50 | p95 | max | Graph request-id (last) |
|---|---|---|---|---|---|---|---|---|
| get_user | 20 | 19 | 1 | 640 ms | 640 ms | 640 ms | 640 ms | 0ce563d0-96a7-4f53-b81f-d45fb3095194 |
| get_last_sign_in | 20 | 0 | 20 | 706 ms | 405 ms | 706 ms | 30105 ms | 7ffd9d6b-b75d-42f7-9fb4-42f032edd534 |
| list_user_groups | 20 | 19 | 1 | 515 ms | 515 ms | 515 ms | 515 ms | 23209aa1-90fa-45e6-b135-57fd771c6b65 |
| list_auth_methods | 20 | 0 | 20 | 717 ms | 344 ms | 560 ms | 717 ms | a1dcd7dd-88f7-4e04-8e22-ba04736e1e66 |
| get_sign_in_logs | 3 | 0 | 3 | 1956 ms | 1195 ms | 1956 ms | 1956 ms | 2b90651a-0fd6-406c-8d20-eec3cb2d445d |
| list_devices | 20 | 0 | 20 | 643 ms | 110 ms | 213 ms | 643 ms | 406b9cd5-9a07-475e-9713-7dc358b23ea4 |
| get_device | 0 | 0 | 0 | pending | pending | pending | pending | n/a |

## Graph request latency per endpoint template (every HTTP request this run, retries included)

| template | requests | p50 | p95 | max | timeouts | non-2xx |
|---|---|---|---|---|---|---|
| user_by_upn | 4 | 139 ms | 273 ms | 273 ms | 0 | 1 |
| guard_directory_roles | 3 | 91 ms | 106 ms | 106 ms | 0 | 0 |
| guard_role_assignments | 3 | 141 ms | 152 ms | 152 ms | 0 | 0 |
| user_member_of | 3 | 103 ms | 146 ms | 146 ms | 0 | 0 |
| user_sign_in_activity | 23 | 254 ms | 654 ms | 705 ms | 0 | 3 |
| users_sign_in_activity_list | 1 | 363 ms | 363 ms | 363 ms | 0 | 0 |
| user_auth_methods | 20 | 343 ms | 558 ms | 715 ms | 0 | 0 |
| sign_in_logs | 3 | 1193 ms | 1953 ms | 1953 ms | 0 | 0 |
| managed_devices | 20 | 108 ms | 211 ms | 641 ms | 0 | 0 |

## Audit log sample (placeholders)

```
{"ts": "2026-10-24T16:42:49.026+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": 200, "graph_calls": 4, "latency_ms": 639, "request_id": "0ce563d0-96a7-4f53-b81f-d45fb3095194", "error": null}
{"ts": "2026-10-24T16:42:49.027+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": null, "graph_calls": 0, "latency_ms": 0, "request_id": null, "error": null}
{"ts": "2026-10-24T16:42:49.027+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": null, "graph_calls": 0, "latency_ms": 0, "request_id": null, "error": null}
```

