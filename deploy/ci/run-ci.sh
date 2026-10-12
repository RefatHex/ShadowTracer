#!/usr/bin/env bash
# One command that runs everything CI should, in a clean state. Mirrors
# .github/workflows/ci.yml's jobs (check-project, shellcheck, build-agent) so
# `act -W .github/workflows/ci.yml` keeps exercising the same checks once
# GitHub Actions is working again - see shadowtracer/docs/DECISIONS.md's
# "Phase 5.5 Item 2" entry for why this script exists instead of a rewrite -
# plus the project's own Python/frontend test suites, which ci.yml does not
# run yet.
#
# Suites run SEQUENTIALLY, not in parallel, on purpose: Postgres roles are
# cluster-global, and every suite's Alembic migrations run
# `ALTER ROLE shadowtracer_app WITH PASSWORD ...`
# (shadowtracer/ingest/alembic/versions/5f408777ad31_*.py) against that same
# shared role even though each suite targets its own isolated database -
# running them concurrently hits a real Postgres `tuple concurrently updated`
# error (reproduced directly while building this script). Each suite's own
# test database name IS session-unique (see MEMORY/project_test_suite_db_race.md
# and its Phase 5.5 follow-up fix), so sequential runs never collide on that
# axis - only true concurrency hits the role-catalog race, which running in
# order avoids entirely.
set -u
cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT="$PWD"

START_TS=$(date +%s)
STEP_RESULTS=()

run_step() {
    local name="$1"; shift
    echo "=== $name ==="
    local t0 step_rc
    t0=$(date +%s)
    ( "$@" )
    step_rc=$?
    local dt=$(( $(date +%s) - t0 ))
    [ "$dt" -ge 0 ] || dt=0  # 1s clock granularity can round a <1s step to -1
    if [ "$step_rc" -eq 0 ]; then
        echo "--- $name: OK (${dt}s)"
        STEP_RESULTS+=("OK    ${dt}s  $name")
    else
        echo "--- $name: FAILED (${dt}s)"
        STEP_RESULTS+=("FAILED ${dt}s  $name")
        print_summary
        exit 1
    fi
}

print_summary() {
    local total=$(( $(date +%s) - START_TS ))
    echo
    echo "=== run-ci.sh summary (${total}s total) ==="
    for line in "${STEP_RESULTS[@]}"; do
        echo "  $line"
    done
}

# --- 1. check-project.sh (Phase 0 invariants) --------------------------
run_step "check-project.sh" bash "$REPO_ROOT/check-project.sh"

# --- 2. shellcheck, our own scripts only --------------------------------
# Only shadowtracer/ and deploy/ - everything else is inherited Wazuh shell
# (93 of the repo's 104 tracked .sh files) that this project doesn't
# maintain and has never shellchecked; check-project.sh's own "our paths"
# convention (':!shadowtracer' ':!deploy') is reused here rather than
# inventing a second definition of "ours".
shellcheck_our_scripts() {
    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "shellcheck not installed - run: sudo apt-get install -y shellcheck" >&2
        return 1
    fi
    local files rc=0
    files=$(git -C "$REPO_ROOT" ls-files 'shadowtracer/*.sh' 'deploy/*.sh')
    [ -n "$files" ] || return 0
    while IFS= read -r f; do
        # -S warning: these scripts' `set -a; source .env; set +a` pattern
        # always trips SC1091 (info) since shellcheck can't statically follow
        # a path built from `dirname "$0"` - real, not a false positive to
        # chase, just not worth failing CI over. Real warnings still fail.
        shellcheck -S warning "$REPO_ROOT/$f" || rc=1
    done <<<"$files"
    return $rc
}
run_step "shellcheck" shellcheck_our_scripts

# --- 3-5. Python test suites (sequential - see header) ------------------
# Each suite's conftest.py hits the real lab Postgres/ClickHouse over their
# published host ports (never a mock) - the lab stack must already be up.
require_lab_up() {
    python3 - <<'EOF'
import socket, sys
for host, port in [("127.0.0.1", 5432), ("127.0.0.1", 8123), ("127.0.0.1", 9094)]:
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, port))
    except OSError:
        print(f"cannot reach {host}:{port} - is the lab up? "
              f"(docker compose -f deploy/lab/docker-compose.yml up -d)", file=sys.stderr)
        sys.exit(1)
    finally:
        s.close()
EOF
}
run_step "lab reachable" require_lab_up

run_pytest() {
    (cd "$REPO_ROOT/$1" && .venv/bin/python -m pytest -q)
}
run_step "ingest tests" run_pytest shadowtracer/ingest
run_step "correlate tests" run_pytest shadowtracer/correlate
run_step "backend tests" run_pytest shadowtracer/console/backend

# --- 6. frontend --------------------------------------------------------
run_frontend() {
    cd "$REPO_ROOT/shadowtracer/console/frontend" || return 1
    npm ci --silent && npx oxlint && npx vitest run && npm run build --silent
}
run_step "frontend (lint, test, build)" run_frontend

# --- 7. agent build, clean ubuntu:22.04 container -----------------------
# Same commands as .github/workflows/ci.yml's build-agent job, run inside a
# throwaway container instead of a GitHub-hosted runner. The repo is bind
# -mounted read-only and copied inside the container before building, so
# this never leaves build artifacts in the host working tree.
#
# `cp -a`, NOT `cp -r`: found the hard way - `cp -r` resets every copied
# file's mtime to "now" in whatever order it happens to traverse them,
# which can make src/external/libyaml's vendored, pre-generated
# `aclocal.m4` look OLDER than its own `Makefile.am`/`configure.ac`. When
# that happens, `make` tries to regenerate it via the `ACLOCAL` rule in
# libyaml's shipped `Makefile` - which hardcodes
# `/build_wazuh/rpmbuild/BUILD/wazuh-agent-4.8.0/src/external/libyaml/config/missing`
# (a leftover absolute path from whatever RPM buildroot produced this
# vendored tarball, for a far older 4.8.0, never regenerated since) - and
# fails with "No such file" since that path exists nowhere outside
# Wazuh's own build infra. `cp -a` preserves the host's original mtimes,
# where aclocal.m4 is already (correctly) newer than its sources, so this
# path is never triggered. Reproduced directly: `cp -r` failed this way
# at `make TARGET=agent` every time; `cp -a` passed every time.
run_agent_build() {
    docker run --rm -v "$REPO_ROOT:/src:ro" ubuntu:22.04 bash -c '
        set -e
        cp -a /src /build
        cd /build
        apt-get update -qq
        apt-get install -y -qq build-essential automake autoconf libtool cmake \
            git curl wget ca-certificates
        cd src
        make deps TARGET=agent
        make TARGET=agent -j"$(nproc)"
    '
}
run_step "agent build (ubuntu:22.04)" run_agent_build

print_summary
echo "All checks passed."
