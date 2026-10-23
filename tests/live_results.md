# Milestone 1 acceptance: LIVE tenant results (layer C, plus live repeats of B1/B3/B5/B6)

Run: 2026-10-22 23:08 UTC  
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
| C5 | get_sign_in_logs alice.test days=7 | PASS | entries=11 failures=6 errorCodes=[50140, 50126, 50140, 50140, 50126, 50140] |
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
| get_user | 20 | 19 | 1 | 600 ms | 600 ms | 600 ms | 600 ms | 763a6ba5-3b01-440b-97ad-70f760b3f458 |
| get_last_sign_in | 20 | 0 | 20 | 757 ms | 1104 ms | 30188 ms | 31068 ms | cdb1e1ee-ed90-4327-8f60-beac4ba5bd3b |
| list_user_groups | 20 | 20 | 0 | pending | pending | pending | pending | a440932b-fd4d-41b0-b0db-540f8fa61b06 |
| list_auth_methods | 20 | 0 | 20 | 324 ms | 340 ms | 511 ms | 518 ms | d86bff25-26af-46ea-84bc-07ba1f77bfeb |
| get_sign_in_logs | 3 | 0 | 3 | 15356 ms | 15356 ms | 16601 ms | 16601 ms | 717ed20d-fe53-4432-965e-06f70c2f2939 |
| list_devices | 20 | 0 | 20 | 289 ms | 155 ms | 289 ms | 605 ms | 2003c3ba-5745-4659-9a12-1ce62da72654 |
| get_device | 0 | 0 | 0 | pending | pending | pending | pending | n/a |

## Graph request latency per endpoint template (every HTTP request this run, retries included)

| template | requests | p50 | p95 | max | timeouts (30 s) | non-2xx |
|---|---|---|---|---|---|---|
| user_by_upn | 4 | 159 ms | 176 ms | 176 ms | 0 | 1 |
| guard_directory_roles | 3 | 169 ms | 174 ms | 174 ms | 0 | 0 |
| guard_role_assignments | 3 | 126 ms | 140 ms | 140 ms | 0 | 0 |
| user_member_of | 3 | 202 ms | 257 ms | 257 ms | 0 | 0 |
| user_sign_in_activity | 23 | 348 ms | 714 ms | 956 ms | 0 | 3 |
| users_sign_in_activity_list | 20 | 567 ms | 990 ms | 1118 ms | 0 | 0 |
| user_auth_methods | 20 | 338 ms | 509 ms | 516 ms | 0 | 0 |
| sign_in_logs | 3 | 15355 ms | 16599 ms | 16599 ms | 0 | 0 |
| managed_devices | 20 | 153 ms | 288 ms | 603 ms | 0 | 0 |

## Audit log sample (placeholders)

```
{"ts": "2026-10-22T23:06:22.898+00:00", "tool": "get_user", "args": {"upn": "<upn>"}, "target": "<upn>", "decision": "allowed", "graph_status": 200, "graph_calls": 4, "latency_ms": 599, "request_id": "763a6ba5-3b01-440b-97ad-70f760b3f458", "error": null}
{"ts": "2026-10-22T23:06:22.900+00:00", "tool": "get_user", "args": {"upn": "<upn>"}, "target": "<upn>", "decision": "allowed", "graph_status": 200, "graph_calls": 0, "latency_ms": 0, "request_id": "763a6ba5-3b01-440b-97ad-70f760b3f458", "error": null}
{"ts": "2026-10-22T23:06:22.900+00:00", "tool": "get_user", "args": {"upn": "<upn>"}, "target": "<upn>", "decision": "allowed", "graph_status": 200, "graph_calls": 0, "latency_ms": 0, "request_id": "763a6ba5-3b01-440b-97ad-70f760b3f458", "error": null}
```

