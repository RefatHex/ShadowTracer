#!/usr/bin/env bash
# Phase 7.8 demo: shared helpers for the deploy/demo/ scripts - big terminal
# banners, env loading, the run-id file, and the compose/ClickHouse/Postgres
# handles. Sourced, never run directly. Everything here targets the TEST tenant.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$DEMO_DIR/../lab" && pwd)"
REPO_DIR="$(cd "$DEMO_DIR/../.." && pwd)"
RUN_ID_FILE="$DEMO_DIR/.demo_run_id"

# Lab env (TEST_TENANT_KEY, CLICKHOUSE_*, POSTGRES_*, TEST_TENANT_ADMIN_*).
set -a; # shellcheck disable=SC1091
source "$LAB_DIR/.env"; set +a

MANAGER=shadowtracer-lab-shadowtracer-worker-test-1
AGENT=shadowtracer-lab-agent-ubuntu-1-1
ATTACKER=shadowtracer-lab-demo-attacker-1
CH=shadowtracer-lab-ch-clickhouse-1-1
PG=shadowtracer-lab-postgres-1
AGENT_ID=060                               # agent-ubuntu-1 on the test manager
TENANT="${TEST_TENANT_KEY:?set TEST_TENANT_KEY in deploy/lab/.env}"

# ---- terminal banners (big, for a recorded screen) ---------------------------
_c_bar='\033[1;36m'; _c_step='\033[1;33m'; _c_ok='\033[1;32m'; _c_warn='\033[1;31m'; _c_off='\033[0m'
bar() { printf "${_c_bar}%s${_c_off}\n" "══════════════════════════════════════════════════════════════════════"; }
banner() {  # banner "<n>" "<title>"
  echo; bar
  printf "${_c_step}  STEP %s  ·  %s${_c_off}\n" "$1" "$2"
  [ -n "${2:-}" ] && printf "${_c_bar}  run-id %s   %s${_c_off}\n" "$(run_id)" "$(date '+%H:%M:%S')"
  bar; echo
}
say()  { printf "   %s\n" "$*"; }
ok()   { printf "${_c_ok}   ✔ %s${_c_off}\n" "$*"; }
warn() { printf "${_c_warn}   ! %s${_c_off}\n" "$*"; }

# ---- run-id ------------------------------------------------------------------
new_run_id() { echo "demo-$(date +%Y%m%d-%H%M%S)" > "$RUN_ID_FILE"; cat "$RUN_ID_FILE"; }
run_id()     { [ -f "$RUN_ID_FILE" ] && cat "$RUN_ID_FILE" || echo "demo-none"; }

chq()  { docker exec "$CH" clickhouse-client -q "$1" 2>/dev/null; }
pgq()  { docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG" psql -U "${POSTGRES_USER:-shadowtracer}" -d "${POSTGRES_DB:-shadowtracer}" -tAc "$1" 2>/dev/null; }

# count test-tenant ClickHouse events carrying this run-id (brute usernames,
# eicar file paths, and load-<run-id> agents all embed it in raw_event).
events_for_run() { chq "SELECT count() FROM shadowtracer.events WHERE tenant_id='$TENANT' AND raw_event LIKE '%$1%'"; }
