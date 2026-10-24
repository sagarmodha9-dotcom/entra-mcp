# Changelog

## v0.1.0 — 2026-10-24 (first tagged release)

**Status, from `EVIDENCE.md`:** 18 tools implemented; 14 live-validated against a real Microsoft 365 tenant (5 of 7 reads,
9 of 11 approval-gated writes; `get_last_sign_in` closed on 2026-10-24 once the test user had signed in); 4 pending (`list_devices`,
`get_device`, `sync_device`, `reboot_device`) because no dedicated test device is enrolled yet. Nothing pending is
described as working anywhere in the repository.

- Approval-gated MCP server for Entra ID / Intune over Microsoft Graph v1.0: 7 reads, 7 identity writes, 2 device actions, 2 approval tools.
- Every write is a proposal; only a person at the Terminal (`entra-mcp approve apr_…`) can approve it; single use, 10-minute TTL,
  SHA-256 integrity at claim time; the model can propose and execute, never approve.
- Two credentials: app-only read client (5 × `*.Read.All`, secret in the macOS Keychain) and a delegated least-privilege operator
  token for writes; the read client cannot send a write template, the write path refuses non-delegated tokens.
- Fixed endpoint allowlist (21 templates), strict schemas, target guard (deny list, directory roles, role assignments, role-assignable
  groups), redacted JSONL audit log, bounded latency (40 s per-tool deadline, wall-clock-bounded transport).
- 109 mocked tests (protocol, authorization incl. prompt-injection arguments, writes/approvals incl. an 8-thread race, timeouts);
  CI on every push with gitleaks over the full history and a planted-secret negative control.
- 12-step simulated demo (real server code, fake Graph transport, fictional tenant) with a 2-minute recording.
- Repository hygiene: real tenant configuration is gitignored (`config.example.toml` committed instead); evidence names the tenant
  generically; CI blocks real identifiers.

Known limitations: see `ACCEPTANCE.md` § Exact remaining blockers (device enrolment; `signInActivity` lag; one deferred TAP re-check;
the Graph sign-in-log endpoint's own 10–19 s latency).
