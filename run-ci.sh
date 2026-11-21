#!/usr/bin/env bash
# Local CI - the single source of truth for running ShadowTracer's Python test suites.
#
# The GitHub Actions workflow (.github/workflows/ci.yml) was removed at the owner's request: on this
# public fork every run failed at the recursive-submodule checkout / agent build, and the owner does
# not want to spend Actions minutes on it. Run this instead.
#
# What it does:
#   1. COLLECT-COUNT GATE: for each suite, `pytest --collect-only` and fail if it collects fewer than
#      the recorded minimum. This is the guard that would have caught the ml suite silently collecting
#      0 tests (a conftest sys.path break) instead of passing as a green "4 passed".
#   2. RUNS each suite SEQUENTIALLY against the running lab (deploy/lab: Postgres/ClickHouse/Kafka).
#      Never in parallel - the lab's Postgres OOM-kills under concurrent suites (see
#      memory: project_postgres_oom). ml and intel need no lab; the rest do.
#
# Usage:
#   ./run-ci.sh                 # collect-count gate, then run every suite
#   ./run-ci.sh --counts-only   # only the collect-count gate (fast; needs no lab)
#   ./run-ci.sh <suite>...      # gate + run just the named suites (console ingest correlate ml intel)
set -uo pipefail
cd "$(dirname "$0")"

declare -A DIR=(
  [console]=shadowtracer/console/backend
  [ingest]=shadowtracer/ingest
  [correlate]=shadowtracer/correlate
  [ml]=shadowtracer/ml
  [intel]=shadowtracer/intel
)
# Recorded MINIMUM collected-test count per suite. Raise it when you add tests; lower it ONLY when you
# deliberately remove some (say why in the commit). A drop below this is a hard failure.
declare -A MIN=( [console]=166 [ingest]=66 [correlate]=74 [ml]=73 [intel]=109 )

ALL=(console ingest correlate ml intel)

counts_only=0
suites=()
for arg in "$@"; do
  case "$arg" in
    --counts-only) counts_only=1 ;;
    console|ingest|correlate|ml|intel) suites+=("$arg") ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done
[ ${#suites[@]} -eq 0 ] && suites=("${ALL[@]}")

py() { echo "${DIR[$1]}/.venv/bin/python"; }

fail=0

echo "=== collect-count gate (minimum tests per suite) ==="
for s in "${suites[@]}"; do
  d="${DIR[$s]}"
  n=$("$(py "$s")" -m pytest "$d/tests" --collect-only -q 2>/dev/null | grep -oE "[0-9]+ tests? collected" | grep -oE "^[0-9]+")
  n=${n:-0}
  if [ "$n" -lt "${MIN[$s]}" ]; then
    echo "  FAIL $s: collected $n < minimum ${MIN[$s]} (tests silently dropped?)"
    fail=1
  else
    echo "  ok   $s: collected $n (>= ${MIN[$s]})"
  fi
done
[ "$fail" -ne 0 ] && { echo "collect-count gate FAILED"; exit 1; }
[ "$counts_only" -eq 1 ] && { echo "collect-count gate passed"; exit 0; }

echo
echo "=== running suites sequentially ==="
declare -A RESULT
for s in "${suites[@]}"; do
  echo "--- $s ---"
  if ( cd "${DIR[$s]}" && .venv/bin/python -m pytest -q ); then
    RESULT[$s]=PASS
  else
    RESULT[$s]=FAIL; fail=1
  fi
done

echo
echo "=== summary ==="
for s in "${suites[@]}"; do printf "  %-10s %s\n" "$s" "${RESULT[$s]}"; done
[ "$fail" -ne 0 ] && { echo "CI FAILED"; exit 1; }
echo "CI PASSED"
