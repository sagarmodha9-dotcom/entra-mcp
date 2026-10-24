# Demo walkthrough (10 minutes)

What a reviewer sees, in the order it happens. Everything below ran against a real Microsoft 365 Business Premium
trial tenant with fictional test users; the outputs quoted are from the recorded runs, lightly trimmed.

## 0. Setup state

```
$ entra-mcp --check
entra-mcp 0.1.0: config ok, secret ok, 18 tools (read + write), audit -> ~/entra-mcp/audit/entra-mcp.jsonl
$ entra-mcp whoami
{'username': 'ops.admin@<tenant>.onmicrosoft.com'}
$ pytest -q
95 passed
```

Two app registrations: `entra-mcp-readonly` (five `*.Read.All` application permissions, client secret in the
Keychain) and `entra-mcp-writes` (delegated permissions only, operator signs in with a device code). The operator
`ops.admin` holds User Administrator + Authentication Administrator and nothing else, and is on the server's deny
list so it can never be a target.

## 1. A read, through Claude Desktop

> **User:** Is alice.test enabled and when did she last sign in?

Claude first sent `alice.test` without a domain; the schema rejected it twice with zero Graph calls. It retried with
the full UPN:

```
get_user          allowed   graph_calls=4   (user + 3 target-guard lookups)
get_last_sign_in  allowed   graph_calls=2   (property + documented list-form cross-check)
```

> **Claude:** Yes, Alice Test is enabled … Last sign-in: Graph has no sign-in activity for her yet …

The server returned `status: unknown` (Microsoft documents `signInActivity` as updating up to 24 hours late), and
the tool description points the model at `get_sign_in_logs` for anything recent. Alice's sign-ins were visible
there within minutes.

## 2. A write, through Claude Desktop, with a human in the loop

> **User:** Revoke all sign-in sessions for carol.test, reason INC0042 lost laptop

> **Claude:** Session revocation for Carol Test … is proposed … nothing has changed yet. To execute it, approve in
> Terminal within the next ~10 minutes: `entra-mcp approve apr_66b27485a693090c`

Audit line: `revoke_sessions  proposed  graph_calls=0`. No write request left the machine.

```
$ entra-mcp approve apr_66b27485a693090c
approved: apr_66b27485a693090c  revoke_sessions -> Carol.Test@…
  graph call: POST /users/{id}/revokeSignInSessions
```

> **User:** Approved, go ahead
> **Claude:** Done — all sessions and refresh tokens for Carol.Test@… are revoked (Graph returned 200, executed as
> ops.admin, request ID 0a6f38de-…)

Audit line: `approve  executed  graph_status=200  request_id=0a6f38de-…`. The proposal is now spent; calling
`approve` again returns `not_executable`.

Worth noticing: Claude then offered to "remotely lock the device in Intune". The server has no such tool; the
suggestion is the model's. That gap between what the model proposes and what the server can do is measured
separately (layer D in `ACCEPTANCE.md`), never papered over.

## 3. What the server refuses, live

| attempt | result | Graph calls |
|---|---|---|
| `disable_account` on the Global Admin | `protected` | 0 |
| `disable_account` on the operator (ops.admin) | `protected` | 0 |
| `approve` on a proposal nobody approved | `not_approved` | 0 |
| approve an expired proposal (1 s TTL) | `expired` | 0 |
| `reboot_device` on an id not in `test_device_ids` | `device_not_allowed` | 0 |
| `get_user` with `alice.test/../admin@…`, `x' or userId ne '…`, `…?$select=*` and 8 more | `invalid_arguments` | 0 |
| a token without delegated scopes reaching the write path | `wrong_token_type` | 0 |

## 4. The seven identity writes, each approved at the keyboard

From `tests/live_results_m23.md` (targets Bob.Test and Carol.Test only; every change reverted):

| tool | Graph | verified by |
|---|---|---|
| disable_account | 204 | read-back `accountEnabled=False` |
| enable_account | 204 | read-back `accountEnabled=True` |
| revoke_sessions | 200 `{value: true}` | documented minutes-to-take-effect |
| reset_password | 202 | `lastPasswordChangeDateTime` moved within 60 s; password shown once, never written |
| create_temporary_access_pass | 201 | lifetime 60, one-time; code shown once, never written (visibility check pending, see ACCEPTANCE §4) |
| add_to_group | 204 | `memberOf` includes sg-vpn-users |
| remove_from_group | 204 | `memberOf` excludes sg-vpn-users |

Then: `bob.test accountEnabled=True`, out of the group; audit log and approval store scanned, no token, password or
TAP present.

## 5. What a hiring manager should look at

1. `EVIDENCE.md`: written only by the live scripts; prints "N of M tools live-validated" itself.
2. `src/entra_mcp/allowlist.py`: the only place a Graph URL is built. 21 fixed templates. Search it for `wipe`.
3. `src/entra_mcp/approvals.py`: the state machine, the file lock, the digest.
4. `tests/test_w_writes.py` W12: concurrency, two-process, replay, tamper, 503, timeout.
5. `README.md` → "Trust boundary and known risks": what this does not protect against.

## 6. Reproduce it yourself

`README.md` → Setup (15 minutes). The scripts refuse to write anything outside your own test users and devices
listed in `config.toml`.
