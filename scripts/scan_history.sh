#!/usr/bin/env bash
# Secret scan over the PUBLISHED git history (every commit, every blob), not just the working tree.
# Exits 1 if anything other than the known redaction regexes / fixtures matches.
set -u
cd "$(git rev-parse --show-toplevel)"
echo "commits: $(git rev-list --all --count)  remote: $(git remote get-url origin 2>/dev/null)"
fail=0
echo "--- 1. values that were actually exposed in chat (must be 0 hits) ---"
if git log -p --all | grep -nE "9M1nbKZ|0-amOrf|Lz6%7b"; then fail=1; else echo "0 hits"; fi
echo "--- 2. secret shapes in any historical blob: client secrets, JWTs, PEM, MSAL cache ---"
hits=$(git log -p --all | grep -nE "8Q~[A-Za-z0-9._~-]{30,}|eyJ[A-Za-z0-9_-]{30,}\.eyJ|-----BEGIN [A-Z ]*PRIVATE KEY|\"refresh_token\"" | grep -vE "redact\.py|test_|fixtures/" || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "0 hits outside redact.py / tests"; fi
echo "--- 3. files that must never have been tracked, in any commit ---"
tracked=$(git log --all --name-only --pretty=format: | sort -u | grep -E "audit/.*\.(jsonl|json)$|tenant\.json|msal_cache|^\.env$|approvals\.lock" || true)
if [ -n "$tracked" ]; then echo "$tracked"; fail=1; else echo "none"; fi
echo "--- 4. literal 8Q~ / eyJ occurrences in HEAD (expected: regexes and fixtures only) ---"
git grep -nE "8Q~|eyJ" -- ':!*.svg' | cut -c1-120
echo "--- 5. gitleaks (if installed) ---"
if command -v gitleaks >/dev/null; then gitleaks git --redact -v . || fail=1; else echo "gitleaks not installed: brew install gitleaks   (optional, repeats 1-3 with 150+ patterns)"; fi
echo; [ $fail -eq 0 ] && echo "HISTORY SCAN: CLEAN" || echo "HISTORY SCAN: FINDINGS ABOVE"
exit $fail
