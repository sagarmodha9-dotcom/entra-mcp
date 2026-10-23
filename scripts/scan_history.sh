#!/usr/bin/env bash
# Secret scan over the PUBLISHED git history (every commit, every blob), not just the working tree.
# Uses `git grep` across all commits with pathspecs, so the scanner's own patterns and the test fixtures are
# excluded by path rather than by hoping a diff line looks different. Exit 1 on any finding.
set -u
cd "$(git rev-parse --show-toplevel)"
echo "commits: $(git rev-list --all --count)  remote: $(git remote get-url origin 2>/dev/null)  HEAD: $(git rev-parse --short HEAD)"
fail=0
REVS=$(git rev-list --all)
NOT_SELF=':!scripts/scan_history.sh'
NOT_TESTS=(':!tests/' ':!src/entra_mcp/redact.py' ':!scripts/scan_history.sh')
echo "--- 1. values that were actually exposed in chat (must be 0 hits anywhere, any commit) ---"
hits=$(git grep -nE "9M1nbKZ|0-amOrf|Lz6%7b" $REVS -- . "$NOT_SELF" || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "0 hits"; fi
echo "--- 2. secret shapes outside redact.py / tests: client secrets, JWTs, private keys, refresh tokens ---"
hits=$(git grep -nE "[A-Za-z0-9]{3}8Q~[A-Za-z0-9._~-]{30,}|eyJ[A-Za-z0-9_-]{20,}\.eyJ|-----BEGIN [A-Z ]*PRIVATE KEY|\"refresh_token\"\s*:" $REVS -- . "${NOT_TESTS[@]}" || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "0 hits"; fi
# self-test: the same pattern must catch a fake secret fed on stdin, or the scan is not trustworthy
if ! printf 'x=Abc8Q~%s\n' "$(printf 'Z%.0s' $(seq 40))" | grep -qE "[A-Za-z0-9]{3}8Q~[A-Za-z0-9._~-]{30,}"; then echo "SELF-TEST FAILED: pattern inert"; fail=1; else echo "(self-test: pattern catches a planted secret shape)"; fi
echo "--- 2b. same shapes inside tests (must be the known fake fixture values only) ---"
git grep -nE "[A-Za-z0-9]{3}8Q~[A-Za-z0-9._~-]{30,}|eyJ[A-Za-z0-9_-]{20,}\.eyJ" HEAD -- tests/ | cut -c1-110 | sort -u
echo "--- 3. files that must never have been tracked, in any commit ---"
tracked=$(git log --all --name-only --pretty=format: | sort -u | grep -E "audit/.*\.(jsonl|json)$|tenant\.json|msal_cache|^\.env$|approvals\.lock" || true)
if [ -n "$tracked" ]; then echo "$tracked"; fail=1; else echo "none"; fi
echo "--- 4. gitleaks (if installed) ---"
if command -v gitleaks >/dev/null; then gitleaks git --redact -v . || fail=1; else echo "gitleaks not installed (optional): brew install gitleaks"; fi
echo; if [ $fail -eq 0 ]; then echo "HISTORY SCAN: CLEAN (exit 0)"; else echo "HISTORY SCAN: FINDINGS ABOVE (exit 1)"; fi
exit $fail
