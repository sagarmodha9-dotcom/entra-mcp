# Milestone 1 acceptance: LIVE tenant results (layer C, plus live repeats of B1/B3/B5/B6)

Run: 2026-10-23 00:18 UTC  
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
| C10 | Claude Desktop end to end (2026-10-22 20:39 UTC) | PASS | allowed calls=['get_user', 'get_last_sign_in'] (graph_calls=[4, 2]); schema rejections before them=2 with 0 Graph calls; other decisions=0; model answered from tool data (enabled=True, last sign-in status reported as unknown, not 'never') |

## Latency per tool (20 calls each, 3 for get_sign_in_logs)

Tool-level wall time. Cache hits are calls answered from the 60 s target-guard cache with zero Graph requests; p50/p95/max are over the network calls only.

| tool | calls | cache hits | network calls | cold | p50 | p95 | max | Graph request-id (last) |
|---|---|---|---|---|---|---|---|---|
| get_user | 20 | 19 | 1 | 966 ms | 966 ms | 966 ms | 966 ms | 0ad5d969-bd62-4268-a31d-81eb1980a685 |
| get_last_sign_in | 20 | 0 | 20 | 1309 ms | 1285 ms | 2283 ms | 2349 ms | 63c25cc3-0f0b-4ffd-8707-956974705108 |
| list_user_groups | 20 | 19 | 1 | 782 ms | 782 ms | 782 ms | 782 ms | 5338b254-5f62-45af-b245-200b014c812c |
| list_auth_methods | 20 | 0 | 20 | 460 ms | 430 ms | 663 ms | 752 ms | 498d1068-cdcc-4483-a97a-3c082a94e756 |
| get_sign_in_logs | 3 | 0 | 3 | 18777 ms | 18777 ms | 61353 ms | 61353 ms | a6ff1803-ed6a-40dd-9cf3-b83e039adf0c |
| list_devices | 20 | 0 | 20 | 356 ms | 175 ms | 356 ms | 863 ms | ff75381d-8101-4d10-80bf-7edd7d3149de |
| get_device | 0 | 0 | 0 | pending | pending | pending | pending | n/a |

## Graph request latency per endpoint template (every HTTP request this run, retries included)

| template | requests | p50 | p95 | max | timeouts (30 s) | non-2xx |
|---|---|---|---|---|---|---|
| user_by_upn | 5 | 150 ms | 369 ms | 369 ms | 0 | 1 |
| guard_directory_roles | 4 | 229 ms | 306 ms | 306 ms | 0 | 0 |
| guard_role_assignments | 4 | 189 ms | 200 ms | 200 ms | 0 | 0 |
| user_member_of | 4 | 183 ms | 239 ms | 239 ms | 0 | 0 |
| user_sign_in_activity | 22 | 601 ms | 1673 ms | 1674 ms | 0 | 1 |
| users_sign_in_activity_list | 21 | 611 ms | 1035 ms | 1767 ms | 0 | 0 |
| user_auth_methods | 20 | 428 ms | 662 ms | 751 ms | 0 | 0 |
| sign_in_logs | 4 | 24452 ms | 30215 ms | 30215 ms | 2 | 0 |
| managed_devices | 20 | 173 ms | 354 ms | 861 ms | 0 | 0 |

## Audit log sample (placeholders)

```
{"ts": "2026-10-23T00:16:00.489+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": 200, "graph_calls": 4, "latency_ms": 964, "request_id": "0ad5d969-bd62-4268-a31d-81eb1980a685", "error": null}
{"ts": "2026-10-23T00:16:00.491+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": null, "graph_calls": 0, "latency_ms": 0, "request_id": null, "error": null}
{"ts": "2026-10-23T00:16:00.491+00:00", "tool": "get_user", "action": null, "target": "<upn>", "actor": null, "args": {"upn": "<upn>"}, "decision": "allowed", "graph_status": null, "graph_calls": 0, "latency_ms": 0, "request_id": null, "error": null}
```

