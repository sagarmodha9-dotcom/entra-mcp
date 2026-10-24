# Acceptance matrix

Status vocabulary, used exactly:

| status | meaning |
|---|---|
| **implemented** | the code exists and is exercised by the mocked suite |
| **mock-tested** | passes in `pytest` with Graph replaced by an HTTP mock (proves server behaviour, nothing about the tenant) |
| **live-tested** | passed against the real Modha AI Labs tenant; recorded by a script in `tests/live_results*.md` / `EVIDENCE.md` |
| **pending** | code is in place; its live row waits on a precondition that has not happened yet |
| **blocked** | cannot progress until something outside the code changes |

Mocked suite: **109 passed** (`tests/unit_results.md`). Live runs: milestone 1 (`live_m1.py`), milestones 2–4 (`live_m23.py`),
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
| Sign-in log query has its own budget: 20 s per attempt, one retry, then `status: unavailable` with a reason (never a crash, never a 60 s+ wait) | `GraphClient.BUDGETS["sign_in_logs"]` | A6 budget test (two attempts at 20 s, clear answer) | measured under the budget (two runs, 2026-10-23 00:4x UTC): 17.4 / 12.8 / 10.7 s and 17.4 / **41.3** / 17.1 s. The 41 s call = one 20 s stall + successful retry: the budget behaved as designed and the 61 s case is gone, but the endpoint's own 10–19 s cost means the **"under 20 s" target is not met for this tool and cannot be from the client side** |
| Hard per-tool wall-clock deadline (`limits.tool_deadline_seconds`, 40 s) covering every Graph request and retry of one call; per-request timeout lowered 30 → 10 s (measured p50 ~1 s, max ~2.5 s); guard lookups that time out fail **closed** (refused), data reads that time out return explicit `unavailable` | `GraphClient.start_deadline/_remaining`, `Engine.run`, `guard.py` | Layer T (11 tests, fake clock + slow transport): no request timeout outlives the deadline, retry loops capped, every read tool bounded when Graph never answers, slow-but-answering endpoints still succeed | **measured once live** (2026-10-23 01:09 UTC): C-LAT PASS, slowest call 31.2 s < 40 s cap. But two `get_last_sign_in` calls still took ~31.2 s **with the 10 s socket timeout confirmed active**, so the stall is not inside the HTTP read: 31.2 = 30.0 + a normal 1.2 s call, and the 30 s constant `requests.timeout` does not cover is name resolution (`getaddrinfo` blocks outside the socket timeout). See next row |
| Transport is wall-clock bounded (deadline held live; stall cause open): the HTTP call runs in a worker thread and is abandoned after `timeout` + 0.5 s whatever it is stuck on (DNS, TLS, socket); one pooled `requests.Session` keeps connections alive so far fewer lookups happen at all. For writes the existing semantics hold: an abandoned write is `uncertain`, never retried | `graph.requests_transport`, `_session()` | T7: a Session that ignores its timeout and sleeps 4× longer is abandoned at the bound | **measured live 2026-10-24 16:44 UTC** (`tests/live_results.md` C-LAT): slowest call `get_last_sign_in` **30,105 ms**, under the 40 s deadline (PASS) — but the ~30 s stall is still there, so the DNS/transport hypothesis is **not confirmed**. The bound works (nothing exceeded the deadline); the cause of the 30 s is still open — next step is per-request timing inside the tool (the `signInActivity` read vs the sign-in-log cross-check) rather than another transport change |

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
| gitleaks 8.30.1 (independent scanner) | 9 commits, 1 finding: rule `jwt`, `tests/test_b_authorization.py:144`, first seen in `08d4e3e`. **Verified synthetic**: decodes to header `{"alg":"RS256","typ":"JWT"}`, payload `{"aud":"https://graph.microsoft.com"}`, signature segment = the ASCII word "signature"; no issuer/tenant/subject/expiry/key material; it exists so B6 can prove JWT shapes are redacted. Exception: `.gitleaks.toml` allowlists that exact literal only (no path exemption: gitleaks applies path allowlists as whole-file skips, which the first draft of the config did and the negative control caught). Rerun with the config: **no leaks found, exit 0**; negative control (a different JWT literal planted in the same file on a scratch branch): **1 leak, caught** | this table; `scripts/scan_history.sh` step 4 now runs gitleaks with the config |
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

## 6. Portfolio demo (simulated)

| item | status |
|---|---|
| `demo/run_demo.py` runs the real engine over the fake transport on a fictional tenant and writes `demo/transcript.json`; 12 steps incl. a denied admin write, the AI's own approve refused, a labelled simulated human approval, execution, replay refused, audit trail; built-in leak scan of the run's audit + approval files | implemented, run clean |
| `demo/record.py` builds self-contained `demo/demo.html` and records it with Playwright → `docs/demo.mp4` (1280×720, h264, 2:01, 3038 frames, ~1.4 MB) and `docs/demo.gif` (960×540, 972 frames, ~7.5 MB) | reproduced four times; **clean-environment run**: fresh copy of the tracked files, new virtualenv, `pip install -e ".[test,demo]"`: 109 tests, identical 12-step transcript, playable video; both files decode end-to-end with ffmpeg; a 12-frame contact sheet (one per step) inspected: every frame carries the SIMULATED badge, steps 1–12 in order, no real identifier |
| gitleaks config cannot conceal real secrets | the exception is two exact literals (the synthetic JWT and the string that spells `fakeSecretValue_ForTestOnly`), no path or rule exemption. Added rule `entra-client-secret` because gitleaks' defaults have no pattern for Entra client secrets. Controls on a scratch branch: a planted Entra secret in `src/`, a planted JWT in `src/`, and a planted Entra secret in the fixture file itself → all three reported (exit 1); real history → no leaks (exit 0) |
| Labelled SIMULATED in the header of every frame, in the first and last step, in the README | yes |
| Shows nothing untested: device actions appear only as "not demonstrated, pending" | yes |
| No real tenant identifiers: tenant id all zeros, domain `contoso-demo.onmicrosoft.com`, users `alice.demo`/`carol.demo`, operator `ops.operator` | yes |

## 7. Sanitized GitHub release checklist

- [x] `.gitignore` excludes `.venv/`, `audit/*.jsonl`, `audit/*.json`, `tests/tenant.json`, `.env`
- [x] Token cache lives outside the repo (`~/Library/Application Support/entra-mcp/`)
- [x] Client secret only in the macOS Keychain. `config.toml` (tenant id, client ids, domain, admin UPNs) is gitignored since 2026-10-24
      and replaced in the repo by `config.example.toml`; the test suite uses a fictional tenant (`tests/fixtures/config.test.toml`).
      Committed evidence names the tenant as `<tenant>.onmicrosoft.com` and ids as `<tenant id>` / `<read app id>` / `<write app id>`.
      The identifiers are not credentials (Microsoft documents tenant and application ids as public-safe) and remain in older commits;
      history is not rewritten. CI (`tests.yml`, job `secrets`) fails if a non-fixture GUID or a real `.onmicrosoft.com` domain is committed.
- [x] Update zips audited: none contained `audit/`, a token cache, `tenant.json` or `.env`; one (`entra-mcp-demo-hardening.zip`) contained `config.toml` and blanked the writes `client_id` on the Mac (no secret involved, the loader refuses secret-like keys); restored by `sed`, and later zips exclude the file
- [x] Pre-commit grep for `8Q~` / `eyJ` shows only the redaction regexes and fixtures
- [x] `scripts/scan_history.sh` reports CLEAN (exit 0) over the pushed history at `c8b1239`, negative control exits 1
- [x] gitleaks over the full history with the one documented exception: no leaks found
- [ ] GitHub secret scanning + push protection enabled (Settings → Code security) — a repository setting; not verifiable from the code
- [x] CI on every push/PR (`.github/workflows/tests.yml`, added 2026-10-24): 109 mocked tests (fails if fewer than 100 run), the
      12-step simulated demo reproduced from the real server code, gitleaks over the full history with the repo config, a planted
      client-secret negative control that must be caught, `scripts/scan_history.sh`, and the tenant-identifier check above
- [x] Result files name only the fictional test users; admin UPNs masked; GUIDs truncated; no IPs; no response bodies
- [x] README states the trust boundary and known risks
- [x] `EVIDENCE.md` is written only by the live scripts and prints its own tool counts
- [x] Create the GitHub repository and push (`git push -u origin main`)
- [x] Carol.Test: portal password reset + TAP deletion, verified `python tests/verify_cleanup.py` → X1–X3 PASS (`b12f175`)
- [x] `live_m1.py` re-run 2026-10-24 closed C2 (5/7 reads live) · [ ] next `live_m23.py` run to close M3-5b and record M2-6 / M2-7
- [ ] Device milestone when a disposable device exists

## 8. Live checks added 2026-10-24 (recorded by `tests/live_m23.py`; pending until its next run)

| id | check | status |
|---|---|---|
| M2-6 | replay: the approval id executed in M3-3 is presented to `approve` again → `not_executable`, zero write requests | pending next run |
| M2-7 | tamper: a human-approved proposal is edited on disk (target changed) → digest check → `tampered`, status `denied`, zero write requests | pending next run |

Both were mock-tested in W12 (replay ×3, tampered args); the live rows exist so the matrix stops saying "not exercised live".

## Exact remaining blockers

1. **A disposable enrolled device.** Options: a macOS VM (UTM/Parallels) enrolled through Company Portal, which first needs an Apple MDM push certificate on the tenant and Intune's MDM authority set; or a Windows 11 VM enrolled manually (no Apple certificate needed). Alice.Test is the licensed user to enrol as. Until then C6, C7, M4-1, M4-2 stay pending and `list_devices`/`get_device`/`sync_device`/`reboot_device` are not described as validated anywhere.
2. ~~Graph property lag on `signInActivity`~~ closed 2026-10-24: C2 PASS after the test user signed in (`live_m1.py`).
3. **One more TAP write** to confirm M3-5b under the polling check: deliberately deferred.
4. ~~Carol.Test credential cleanup~~ closed: X1–X3 PASS in `b12f175`.
5. **Layer D** measurements: not a blocker for the release, listed so the README never implies it was done.
