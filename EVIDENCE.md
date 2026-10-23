# Evidence matrix: milestone 1 (read-only)

Filled only by `tests/live_m1.py` from real Graph calls. 'Supported' is never written by hand.  
Last live run: 2026-10-23 01:11 UTC. Mocked test totals are in `tests/unit_results.md` and are not evidence of tenant behaviour.

**Status: 4 of 7 tools live-validated, 3 pending, 0 failed.** Not all seven are validated until the device rows pass.

| tool | Graph endpoint | permission (app) | licence | role needed | live result (date) | latency p50 / p95 | limitations |
|---|---|---|---|---|---|---|---|
| get_user | GET /users/{upn}?$select=… | User.Read.All | Free | none | supported (2026-10-23) | 583 / 583 ms | no lockout flag exists in Graph |
| get_last_sign_in | GET /users/{id}?$select=signInActivity (+ list form cross-check) | AuditLog.Read.All + User.Read.All | P1 | none | pending (2026-10-23) | 1073 / 31052 ms | property updates up to 24 h late (documented); 204/empty -> status=unknown, never 'never signed in' |
| list_user_groups | GET /users/{id}/memberOf | Directory.Read.All | Free | none | supported (2026-10-23) | pending | direct memberships only |
| list_auth_methods | GET /users/{id}/authentication/methods | UserAuthenticationMethod.Read.All | not stated by MS | none (app) | supported (2026-10-23) | 310 / 467 ms | phone masked, ids dropped |
| get_sign_in_logs | GET /auditLogs/signIns?$filter=userId eq '{id}' and createdDateTime ge … | AuditLog.Read.All | P1 | none (app) | supported (2026-10-23) | 8531 / 15224 ms | 30-day retention; no IPs returned; slow endpoint, 10-19 s per call with occasional stalls; 20 s per-attempt budget, one retry, inside the 40 s tool deadline |
| list_devices | GET /deviceManagement/managedDevices[?$filter=userPrincipalName eq '{upn}'] | DeviceManagementManagedDevices.Read.All | Intune | none (app) | pending (2026-10-23) | 159 / 208 ms | UPN filter unverified until a device exists |
| get_device | GET /deviceManagement/managedDevices/{id} | DeviceManagementManagedDevices.Read.All | Intune | none (app) | pending (2026-10-23) | pending | pending until a dedicated test device is enrolled |

Pending rows are pending because their precondition is not met yet (a sign-in by the test user, an Authenticator registration, an enrolled dedicated test device), not because the code is missing. They are closed only by a later run of the same script.

## Milestones 2-4: approvals, identity writes, device actions

Last live run: 2026-10-22 23:55 UTC. Written only by `tests/live_m23.py`.  
**Status: 9 of 11 milestone 2-4 tools live-validated, 2 pending, 0 failed.** Device actions stay pending until a dedicated test device is enrolled.

| tool | Graph call | delegated permission | operator role | live result (date) | notes |
|---|---|---|---|---|---|
| disable_account | PATCH /users/{id} {accountEnabled:false} | User.EnableDisableAccount.All (delegated) | User Administrator | supported (2026-10-22) | graph_status=204 request_id=b3c9e62c… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; re… |
| enable_account | PATCH /users/{id} {accountEnabled:true} | User.EnableDisableAccount.All (delegated) | User Administrator | supported (2026-10-22) | graph_status=204 request_id=641b6f63… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; re… |
| reset_password | POST /users/{id}/authentication/methods/{mid}/resetPassword | UserAuthenticationMethod.ReadWrite.All (delegated only) | Password/User Administrator | supported (2026-10-22) | graph_status=202 request_id=d2412ad1… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; ac… |
| create_temporary_access_pass | POST /users/{id}/authentication/temporaryAccessPassMethods | UserAuthenticationMethod.ReadWrite.All (delegated) | Authentication Administrator | supported (2026-10-22) | graph_status=201 request_id=874a030f… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; li… |
| revoke_sessions | POST /users/{id}/revokeSignInSessions | User.RevokeSessions.All (delegated) | Helpdesk/User Administrator | supported (2026-10-22) | graph_status=200 request_id=d56f886b… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; va… |
| add_to_group | POST /groups/{gid}/members/$ref | GroupMember.ReadWrite.All (delegated) | User Administrator | supported (2026-10-22) | graph_status=204 request_id=f2852f4a… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; me… |
| remove_from_group | DELETE /groups/{gid}/members/{id}/$ref | GroupMember.ReadWrite.All (delegated) | User Administrator | supported (2026-10-22) | graph_status=204 request_id=55dba119… executed_as=<masked>@ModhaAILabs.onmicrosoft.com; me… |
| sync_device | POST /deviceManagement/managedDevices/{id}/syncDevice | DeviceManagementManagedDevices.PrivilegedOperations.All (delegated) | Intune Help Desk Operator | pending (2026-10-22) | pending: test_device_ids=[], no device enrolled |
| reboot_device | POST /deviceManagement/managedDevices/{id}/rebootNow | DeviceManagementManagedDevices.PrivilegedOperations.All (delegated) | Intune Help Desk Operator | pending (2026-10-22) | pending with M4-1; never run on the everyday Mac |
| approve | none (executes a human-approved proposal) | n/a | n/a | supported (2026-10-22) | not_approved; Graph calls during refusal=0 |
| list_pending_approvals | none | n/a | n/a | supported (2026-10-22) | 0 pending after denials |


Claude Desktop end to end (C10): PASS on 2026-10-22; allowed calls=['get_user', 'get_last_sign_in'] (graph_calls=[4, 2]); schema rejections before them=2 with 0 Graph calls; other decisions=0; model answered from tool data (enabled=True, last sign-in status reported as unknown, not 'never').
Claude Desktop write flow (W-E2E): PASS on 2026-10-22; tool=revoke_sessions target=<test user> proposal graph_calls=0; approved_by=cli:sagarmodha (Terminal), executed_as=<operator>, approve graph_status=200, request_id=0a6f38de-1136-4a11-aab7-532731a1b09c.
