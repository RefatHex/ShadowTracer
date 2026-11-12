#!/usr/bin/env bash
# Phase 7.8 demo: run one scenario step against the TEST tenant, with a big
# terminal banner and a live confirmation that it fired. Each step tags its data
# with the current run-id (deploy/demo/.demo_run_id, set by demo-reset.sh).
#
#   deploy/demo/demo-scenario.sh brute   # SSH brute force from the attacker box
#   deploy/demo/demo-scenario.sh eicar   # EICAR file -> FIM -> threat-intel hit
#   deploy/demo/demo-scenario.sh replay  # replay one recorded Windows dataset
#   deploy/demo/demo-scenario.sh load    # 500 events/s for 2 minutes
#
# Atomic Red Team steps are run by the owner's own script - not here.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-common.sh"

EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# wait until `events_for_run <marker>` reports >= $2 rows (or time out at $3 s)
wait_for() {  # marker min_rows timeout_s
  local marker="$1" want="$2" timeout="${3:-40}" waited=0 n=0
  while [ "$waited" -lt "$timeout" ]; do
    n="$(events_for_run "$marker")"; n="${n:-0}"
    [ "$n" -ge "$want" ] && { ok "$n events for '$marker' in ClickHouse (wanted >= $want)"; return 0; }
    printf "\r   … %s events so far (%ss)   " "$n" "$waited"; sleep 3; waited=$((waited+3))
  done
  echo; warn "only $n events for '$marker' after ${timeout}s (wanted >= $want)"; return 1
}

step_brute() {
  banner 2 "SSH BRUTE FORCE  (attacker box -> agent-ubuntu-1)"
  local rid; rid="$(run_id)"
  docker inspect -f '{{.State.Running}}' "$ATTACKER" 2>/dev/null | grep -q true \
    || { warn "demo-attacker not running - start it: (cd deploy/lab && docker compose --profile demo up -d demo-attacker)"; return 1; }
  say "15 failed logins with usernames tagged ${rid} (also trips Wazuh's 5712 brute-force rule)"
  docker exec "$ATTACKER" sh -c "
    for i in \$(seq 1 15); do
      ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 ${rid}-u\$i@agent-ubuntu-1 true 2>/dev/null || true
    done" || true
  wait_for "$rid" 10 40
}

step_eicar() {
  banner 3 "EICAR FILE  ->  FIM  ->  THREAT-INTEL HIT"
  local rid; rid="$(run_id)" f="/root/${rid}-eicar.com"
  say "drop the EICAR test file at ${f} on agent-ubuntu-1 (its sha256 is in the TI high list)"
  docker exec "$AGENT" sh -c "printf '%s' '$EICAR' > $f" && ok "written"
  say "trigger an on-demand syscheck scan (no agent restart)"
  docker exec "$MANAGER" /var/ossec/bin/agent_control -r -u "$AGENT_ID" >/dev/null 2>&1 || true
  say "expect rule 110012 - 'Threat intel (high confidence): FIM file sha256 … is a known indicator'"
  wait_for "$rid-eicar" 1 60
}

step_replay() {
  banner 4 "REPLAY  ·  one recorded Windows dataset"
  say "replaying ONE recorded dataset through the test manager as a dedicated replay agent (<=150 ev/s)"
  cd "$REPO_DIR/shadowtracer/ml"
  # Replay exactly one dataset (prefer a Windows EVTX sample, else the first planned one).
  CLICKHOUSE_HOST=127.0.0.1 POSTGRES_HOST=127.0.0.1 .venv/bin/python - <<'PY'
from shadowtracer_ml import replay, db
items = replay.plan()
if not items:
    raise SystemExit("no replayable datasets found - run: python -m shadowtracer_ml.datasets download evtx")
chosen = next((x for x in items if x[0].startswith("evtx:")), items[0])
ds, tech, fmt, files = chosen[0], chosen[1], chosen[2], chosen[3]
print(f"   dataset: {ds}  ({len(files)} file(s), format {fmt})")
res = replay.replay(db.engine(), db.clickhouse(), ds, tech, files, rate=150, fmt=fmt)
print("   replay result:", res)
PY
  ok "replay finished - find it in ClickHouse ml_replay_events and as a new incident on the replay agent"
}

step_load() {
  banner 5 "LOAD  ·  500 events/s for 2 minutes"
  local rid; rid="$(run_id)"
  local net; net="$(docker network ls --format '{{.Name}}' | grep -i 'lab' | head -1)"
  say "feeding the TEST tenant via TCP syslog to the manager (backpressured, no drops), tagged load-${rid}"
  # Run the generator in a throwaway container on the lab network so it can reach the
  # manager's internal syslog listener; the host can't write the root-owned alerts.json.
  docker run --rm --network "$net" -v "$REPO_DIR:/repo:ro" python:3.12-slim \
    python3 /repo/deploy/load/generate_load.py --target syslog --protocol tcp \
    --host shadowtracer-worker-test --port 5515 --rate 500 --duration 120 --run-id "$rid" 2>&1 | tail -4 \
    || warn "load step exited non-zero (mem guard?)"
  wait_for "load-$rid" 100 60
}

case "${1:-}" in
  brute)  step_brute ;;
  eicar)  step_eicar ;;
  replay) step_replay ;;
  load)   step_load ;;
  *) echo "usage: $0 {brute|eicar|replay|load}" >&2; exit 2 ;;
esac
