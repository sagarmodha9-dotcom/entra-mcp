# Acceptance matrix

Status vocabulary, used exactly:

| status | meaning |
|---|---|
| **implemented** | the code exists and is exercised by the mocked suite |
| **mock-tested** | passes in `pytest` with Graph replaced by an HTTP mock (proves server behaviour, nothing about the tenant) |
| **live-tested** | passed against the real Modha AI Labs tenant; recorded by a script in `tests/live_results*.md` / `EVIDENCE.md` |
| **pending** | code is in place; its live row waits on a precondition that has not happened yet |
| **blocked** | cannot progress until something outside the code changes |

Mocked suite: **97 passed** (`tests/unit_results.md`). Live runs: milestone 1 (`live_m1.py`), milestones 2–4 (`live_m23.py`),
Claude Desktop recorder (`record_c10.py`). Dates are in the result files. No live identity write was performed to fill this
matrix; every live row below cites a run that already happened.

## 1. Approval integrity and execution safety

| item | implemented | mock-tested | live-tested | notes |
|---|---|---|---|---|
| CLI approval and MCP execution are distinct steps | `approvals.human_approve` (CLI only) vs `claim_for_execution` (MCP `approve`) | W2, W3 | M2-2 (approve without a human → refused, 0 Graph calls); W-E2E (Terminal approval then execution, request id recorded) | the model can propose and execute, never approve |
| Cross-process locking | `fcntl.flock` on `audit/approvals.lock` around every load-modify-save | W12 two-store test, W12 8-thread race (1 executes, 7 refused) | not exercised live (one server process ran) | state is file-backed; a second instance after "restart" sees `executed` |
| Replay prevention (single use) | status machine: approved → executed/failed/uncertain, all terminal | W3, W12 replay ×3, CLI re-approve refused, denied cannot be approved | M2-3 (expired), M2-2 (unapproved); executed-then-replay not attempted live | |
| Proposal integrity | SHA-256 over (tool, args, target, graph call) checked at claim; mismatch → `denied` | W12 tampered-args test | not exercised live | protects against edits, not against the OS user forging a whole record (see README trust boundary) |
| Failed / uncertain outcomes | Graph 4xx/5xx → `failed`; no response → `uncertain` with verify-by-read instruction; both spend the proposal | W12 503 test, W12 timeout test | one live 400 (TAP lifetime 10 < policy 60) produced a failed outcome and no retry on the earlier build; the current labels are mock-tested only | |
| Audit line per execution carries action, target, operator, outcome, Graph status, request id, no credentials | `audit.FIELDS` + `ToolError.context` | W12 self-contained-line test, B6 | B6 (117 lines) and B6-w (25 lines) scanned live for tokens/secrets: none | the live W-E2E line predates the `action`/`actor` fields; next Desktop run records them |

## 2. No automatic retry of non-idempotent writes

| item | implemented | mock-tested | live-tested |
|---|---|---|---|
| Write client sends each write exactly once (`max_retries=0`), no retry on timeout, 429 or 5xx | `graph.WriteGraphClient` | W12: 503 → one request; timeout → one request, `uncertain` | not exercised live (no failures occurred in the recorded runes except the 400 above, which was not retried) |
| Read client still retries 429/503/timeouts with backoff (idempotent GETs) | `graph.GraphClient` | A6 ×3 | C-layer runs recovered from 30 s stalls on `get_last_sign_in` by retry |
| Sign-in log query has its own budget: 20 s per attempt, one retry, then `status: unavailable` with a reason (never a crash, never a 60 s+ wait) | `GraphClient.BUDGETS["sign_in_logs"]` | A6 budget test (two attempts at 20 s, clear answer) | the 61 s outlier (`get_sign_in_logs`, next-day run) is what this closes; not yet observed live under the new budget |

## 3. Sanitized output and credential rotation

| item | status | evidence |
|---|---|---|
| Redaction filter on every audit line, approval record and error (JWTs, secret shapes, phone numbers, IPs, registered secret values) | implemented, mock-tested (B6), live-tested (B6, B6-w) | `redact.py`; audit and approval files scanned after each live run |
| Results writers mask non-test UPNs, truncate GUIDs, drop response bodies | implemented, live-tested | `tests/live_results*.md` reviewed; admin activity reduced to counts in `live_results_validate.md` |
| Live scripts never display generated passwords/TAPs, in any form (no reveal flag exists) | implemented | the first build printed them in clear; two of Carol's temporary passwords and one TAP were then pasted into a chat from Terminal output. A masked mode with `--show-secrets` followed; that flag is now removed. Only length and character-class count are printed |
| Read app client secret | **rotated** (live): first secret partially exposed in chat → deleted in the portal, new secret issued, stored in Keychain (length 40 verified) | this conversation; `security find-generic-password` |
| Carol.Test temporary passwords (2) and TAP (1) exposed via pasted output | **invalidated, verified read-only** (`verify_cleanup.py`, commit `b12f175`): X1 PASS: portal password reset at 2026-10-23T00:32:34Z, after the last tool-issued reset at 23:54:50Z, so both pasted passwords are dead; X2 PASS: TAP method deleted in the portal at ~00:40 UTC and a fresh `list_auth_methods` read returns `['password']`; X3 PASS: rotated read secret present in Keychain (length 40). Accurate timeline: the TAP was created 23:55 UTC with a 60-minute lifetime and was still **usable** (expiry 00:55 UTC) when it was deleted; an earlier note in this file calling it expired was wrong by an hour. Two intermediate commits (`c8b1239`, `12eab06`) carry messages claiming X1–X3 PASS while their content shows FAIL rows; history is not rewritten, this row is the correction | test account, no licence, no data |
| Operator refresh token on disk | implemented: MSAL cache, mode 0600, outside the repo; `entra-mcp logout` deletes it | README trust boundary |
| Repo pre-commit secret scan | clean: the only `8Q~`/`eyJ` matches are the redaction regexes and test fixtures | `grep` run before the first commit |
| Published git history scan (every commit, every blob, not just HEAD) | `scripts/scan_history.sh`: `git grep` over every commit with path exclusions, exposed values, secret shapes, never-tracked files, pattern self-test, optional gitleaks | run on a fresh clone of `origin/main` at `c8b1239` (6 commits): sections 1–3 all 0 hits / none, **exit 0**. Negative control: a scratch commit with a planted fake secret made the scanner exit 1; after removing it, exit 0 again. The first version of the scanner (commit `7aa4642`) grepped `git log -p` and matched its own pattern lines; it was replaced before any CLEAN result was recorded |
| Commit `c8b1239` is mislabeled | its message says "X1-X3, history scan clean" but its content is the X1/X2 **FAIL** rows from the 00:30 UTC run (portal cleanup had not happened yet and the scan never ran because the `&&` chain stopped). The next commit carries the real result; history is not rewritten | this table |

## 4. Temporary Access Pass visibility (M3-5b)

| item | status |
|---|---|
| `create_temporary_access_pass` → Graph 201, code returned once, never persisted | **live-tested** (M3-5) |
| TAP appears in `list_auth_methods` | **live-observed, not yet live-tested by the script**: the first live check read immediately after the 201 and saw `['password']` (read-after-write lag); `verify_cleanup.py` at 00:30 UTC, 25 minutes later, read `['password', 'temporaryAccessPass']` for the same user, so the TAP did become visible with its type and without its code. The script check now polls up to 30 s. Mocked regression test A7 covers the shape (type reported, `isUsable` reported, id/code/lifetime never returned). Closing the live row needs one more TAP write, deliberately deferred |

## 5. Remaining read-only and device checks

| check | status | what closes it |
|---|---|---|
| C2 `get_last_sign_in` for Alice returns a timestamp | **pending**: Graph's `signInActivity` is documented as updating up to 24 h after a sign-in; still `unknown` 4 h after her first sign-in; the tool returns `status: unknown` honestly meanwhile | `python tests/live_m1.py` the next day |
| C4, C5 (auth methods, sign-in logs) | live-tested | |
| C6 `list_devices`, C7 `get_device` | **blocked**: no device enrolled in Intune | enrol a disposable device (see blockers) |
| M4-0 device outside `test_device_ids` refused with 0 Graph calls | live-tested | |
| M4-1 `sync_device`, M4-2 `reboot_device` | **blocked**: same device precondition, plus the device id must be listed in `config.toml` | |
| Layer D (model prompt-injection measurements D1–D5) | **not started**: needs seeded hostile strings in test-user fields and ten repetitions each; reported as counts, separately from server guarantees | after device work, or independently |

## 6. Sanitized GitHub release checklist

- [x] `.gitignore` excludes `.venv/`, `audit/*.jsonl`, `audit/*.json`, `tests/tenant.json`, `.env`
- [x] Token cache lives outside the repo (`~/Library/Application Support/entra-mcp/`)
- [x] Client secret only in the macOS Keychain; `config.toml` holds tenant id, client ids and domain (public-safe identifiers)
- [x] Pre-commit grep for `8Q~` / `eyJ` shows only the redaction regexes and fixtures
- [x] `scripts/scan_history.sh` reports CLEAN (exit 0) over the pushed history at `c8b1239`, negative control exits 1
- [ ] GitHub secret scanning + push protection enabled (Settings → Code security)
- [x] Result files name only the fictional test users; admin UPNs masked; GUIDs truncated; no IPs; no response bodies
- [x] README states the trust boundary and known risks
- [x] `EVIDENCE.md` is written only by the live scripts and prints its own tool counts
- [x] Create the GitHub repository and push (`git push -u origin main`)
- [x] Carol.Test: portal password reset + TAP deletion, verified `python tests/verify_cleanup.py` → X1–X3 PASS (`b12f175`)
- [ ] Next-day `live_m1.py` run to close C2; next scheduled `live_m23.py` run to close M3-5b
- [ ] Device milestone when a disposable device exists

## Exact remaining blockers

1. **A disposable enrolled device.** Options: a macOS VM (UTM/Parallels) enrolled through Company Portal, which first needs an Apple MDM push certificate on the tenant and Intune's MDM authority set; or a Windows 11 VM enrolled manually (no Apple certificate needed). Alice.Test is the licensed user to enrol as. Until then C6, C7, M4-1, M4-2 stay pending and `list_devices`/`get_device`/`sync_device`/`reboot_device` are not described as validated anywhere.
2. **Graph property lag** on `signInActivity` (documented 24 h): closes itself; re-run `live_m1.py`.
3. **One more TAP write** to confirm M3-5b under the polling check: deliberately deferred.
4. ~~Carol.Test credential cleanup~~ closed: X1–X3 PASS in `b12f175`.
5. **Layer D** measurements: not a blocker for the release, listed so the README never implies it was done.
