#!/usr/bin/env bash
# Fast pre-push gate. Opt-in - install with:
#   ln -sf ../../deploy/ci/pre-push-hook.sh .git/hooks/pre-push
#
# Deliberately NOT the full run-ci.sh: the ingest/correlate/backend pytest
# suites hit the real lab Postgres/ClickHouse (never a mock, see those
# suites' own conftest.py docstrings) and take ~1-4 minutes each
# sequentially - too slow for a gate on every push, and there is no
# separate pure-unit tier to run instead (every test in this project goes
# through conftest.py's real-database fixtures, even ones that don't touch
# the DB in the test body itself - verified directly: a single non-DB test
# file still pays the full session-fixture cost). Those suites are covered
# by deploy/ci/run-ci.sh and CI instead.
#
# What this DOES run, all fast (checked: ~6s total) and none needing the
# lab stack up:
#   - check-project.sh (Phase 0 invariants)
#   - shellcheck on shadowtracer/ and deploy/'s own scripts
#   - frontend lint + unit tests (oxlint, vitest - no backend dependency)
set -u
repo_root="$(git rev-parse --show-toplevel)" || exit 1
cd "$repo_root" || exit 1

fail=0

echo "=== check-project.sh ==="
bash check-project.sh || fail=1

echo "=== shellcheck ==="
if command -v shellcheck >/dev/null 2>&1; then
    files=$(git ls-files 'shadowtracer/*.sh' 'deploy/*.sh')
    if [ -n "$files" ]; then
        while IFS= read -r f; do
            shellcheck -S warning "$f" || fail=1
        done <<<"$files"
    fi
else
    echo "shellcheck not installed (sudo apt-get install -y shellcheck) - skipping" >&2
fi

echo "=== frontend lint + tests ==="
(cd shadowtracer/console/frontend && npx oxlint && npx vitest run) || fail=1

if [ "$fail" -ne 0 ]; then
    echo "pre-push: FAILED - fix the above, or 'git push --no-verify' to bypass" >&2
    exit 1
fi
echo "pre-push: OK"
