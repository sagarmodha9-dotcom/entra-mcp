# Milestone 1 acceptance: LIVE tenant results (layer C, plus live repeats of B1/B3/B5/B6)

Run: 2026-10-23 01:11 UTC  
Tenant: 62130626… (modhaailabs.onmicrosoft.com, Microsoft 365 Business Premium trial: Entra ID P1 + Intune)  
App: e3b405e7… entra-mcp-readonly, client credentials, roles: AuditLog.Read.All, DeviceManagementManagedDevices.Read.All, Directory.Read.All, User.Read.All, UserAuthenticationMethod.Read.All  
Path exercised: the same Engine the MCP server runs (schemas -> gate -> allowlisted GETs -> audit), without stdio.

These are real Microsoft Graph responses. Mocked results live separately in `tests/unit_results.md`.

Sanitized by the results writer: GUIDs truncated, only the fictional test users appear by name, no tokens, no phone numbers, no IP addresses, no response bodies beyond the fields named in each pass condition.

| id | test | result | detail |
|---|---|---|---|
| B5 | scope ceiling: real token holds no write scope | PASS | roles=['AuditLog.Read.All', 'DeviceManagementManagedDevices.Read.All', 'Directory.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All'] write_scopes=none |
| C1 | get_user alice.test | PASS | accountEnabled=True department=IT Support |
| C2 | get_last_sign_in alice.test | PENDING | status=unknown: Graph returned no signInActivity for this user on both the single-user and the list query. This can mean the user has never signed in, or that the property has not updated yet: Microsoft documents that signInActivity can take up to 24 hours. Not treated as proof of either. For recent activity use get_sign_in_logs. Microsoft documents signInActivity as updating up to 24 hours after the sign-in; re-run the next day to close this row. |
| C2b | get_last_sign_in on a user without history returns an explicit status | PASS | bob.test -> status=unknown |
| C3 | list_user_groups alice.test | PASS | groups=['Modha AI Labs', 'sg-helpdesk-test', 'sg-vpn-users'] (error=None) |
| C4 | list_auth_methods alice.test (types only, phone masked) | PASS | types=['password', 'microsoftAuthenticator'] |
| C5 | get_sign_in_logs alice.test days=7 | PASS | entries=12 failures=6 errorCodes=[50140, 50126, 50140, 50140, 50126, 50140] |
| C5b | sign-in rows carry no IP address | PASS | checked result JSON |
| C6 | list_devices | PENDING | endpoint 200, devices=0 (no dedicated test device enrolled yet; stays pending by design) |
| C7 | get_device | PENDING | pending with C6 |
| C8 | unknown user maps to not_found | PASS | not_found: Not found (404): no user or device with that identifier in this tenant. (Request_ResourceNotFound: Resource '<masked>@modhaailabs.onmicrosoft.com' does not exist or one of its queried reference-property objects are not present.) |
| C9 | admin target refused by the guard (B1 live) | PASS | protected; graph_calls=0; audit decision=refused |
| B3 | hostile arguments rejected at the server with zero Graph calls (live) | PASS | rejected 11/11; graph_calls=0 |
| B6 | audit log holds no token or secret after the run (live) | PASS | 117 audit lines scanned |
| C-LAT | no tool call exceeded tool_deadline_seconds=40 s (measured) | PASS | slowest call this run: get_last_sign_in 31205 ms; per-request timeout 10 s, sign-in log 20 s/attempt; p50 per tool: get_user 583, get_last_sign_in 1073, list_auth_methods 310, get_sign_in_logs 8531, list_devices 159 |
| C10 | Claude Desktop end to end (2026-10-22 20:39 UTC) | PASS | allowed calls=['get_user', 'get_last_sign_in'] (graph_calls=[4, 2]); schema rejections before them=2 with 0 Graph calls; other decisions=0; model answered from tool data (enabled=True, last sign-in status reported as unknown, not 'never') |

## Latency per tool (20 calls each, 3 for get_sign_in_logs)

Tool-level wall time. Cache hits are calls answered from the 60 s target-guard cache with zero Graph requests; p50/p95/max are over the network calls only.

| tool | calls | cache hits | network calls | cold | p50 | p95 | max | Graph request-id (last) |
|---|---|---|---|---|---|---|---|---|
| get_user | 20 | 19 | 1 | 583 ms | 583 ms | 583 ms | 583 ms | ee0b906f-b011-4bbe-876d-38f0acb47055 |
| get_last_sign_in | 20 | 0 | 20 | 1098 ms | 1073 ms | 31052 ms | 31205 ms | 8cfa2256-84ac-4900-9126-315c64a553db |
| list_user_groups | 20 | 20 | 0 | pending | pending | pending | pending | c44cbfec-6096-4d2b-b677-1fa1c12e0dd7 |
| list_auth_methods | 20 | 0 | 20 | 431 ms | 310 ms | 467 ms | 485 ms | fb9b1dbe-8b83-467a-b3ac-f6bf33d0555e |
| get_sign_in_logs | 3 | 0 | 3 | 8531 ms | 8531 ms | 15224 ms | 15224 ms | 99c580b8-8212-4023-ae25-62ca5af67e30 |
| list_devices | 20 | 0 | 20 | 208 ms | 159 ms | 208 ms | 253 ms | 9bd1bfe3-6412-4d33-9336-a42932aa8f88 |
| get_device | 0 | 0 | 0 | pending | pending | pending | pending | n/a |

## Graph request latency per endpoint template (every HTTP request this run, retries included)

| template | requests | p50 | p95 | max | timeouts | non-2xx |
|---|---|---|---|---|---|---|
| user_by_upn | 4 | 160 ms | 215 ms | 215 ms | 0 | 1 |
| guard_directory_roles | 3 | 141 ms | 249 ms | 249 ms | 0 | 0 |
| guard_role_assignments | 3 | 158 ms | 214 ms | 214 ms | 0 | 0 |
| user_member_of | 3 | 155 ms | 171 ms | 171 ms | 0 | 0 |
| user_sign_in_activity | 23 | 364 ms | 641 ms | 755 ms | 0 | 2 |
| users_sign_in_activity_list | 21 | 613 ms | 756 ms | 958 ms | 0 | 0 |
| user_auth_methods | 20 | 308 ms | 465 ms | 483 ms | 0 | 0 |
| sign_in_logs | 3 | 8529 ms | 15222 ms | 15222 ms | 0 | 0 |
| managed_devices | 20 | 158 ms | 207 ms | 252 ms | 0 | 0 |

## Audit log sample (placeholders)

```
{"ts": "2026-10-23T01:09:52.420+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": 200, "graph_calls": 4, "latency_ms": 581, "request_id": "ee0b906f-b011-4bbe-876d-38f0acb47055", "error": null}
{"ts": "2026-10-23T01:09:52.422+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": null, "graph_calls": 0, "latency_ms": 0, "request_id": null, "error": null}
{"ts": "2026-10-23T01:09:52.422+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": null, "graph_calls": 0, "latency_ms": 0, "request_id": null, "error": null}
```

