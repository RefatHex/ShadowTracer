#!/usr/bin/env bash
# Phase 7.8 demo: background "normal" traffic for the TEST tenant so the anomaly
# model has a recent baseline and the attack bursts stand out. Benign events from
# the anonymised corpus, fed to the test manager over TCP syslog at a low rate.
# Runs as a detached container on the lab network (the host can't write the
# root-owned alerts.json); a later attack step is what the model sees as abnormal.
#
#   deploy/demo/demo-warmup.sh [start]   # default: ~25 ev/s for 10 min, backgrounded
#   deploy/demo/demo-warmup.sh stop      # stop it
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-common.sh"

NAME=demo-warmup
RATE="${DEMO_WARMUP_RATE:-25}"
DURATION="${DEMO_WARMUP_DURATION:-600}"

stop() {
  if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    docker stop "$NAME" >/dev/null 2>&1 || true; ok "warmup stopped"
  else
    say "no warmup running"
  fi
}

case "${1:-start}" in
  stop) banner 1 "WARMUP STOP"; stop; exit 0 ;;
  start) : ;;
  *) echo "usage: $0 {start|stop}" >&2; exit 2 ;;
esac

banner 1 "WARMUP  ·  background normal traffic (${RATE} ev/s, ${DURATION}s)"
docker ps --format '{{.Names}}' | grep -qx "$NAME" && { warn "warmup already running (deploy/demo/demo-warmup.sh stop)"; exit 0; }

rid="$(run_id)"
net="$(docker network ls --format '{{.Name}}' | grep -i 'lab' | head -1)"
say "feeding benign corpus events to the TEST tenant via TCP syslog, tagged load-${rid}-warm"
docker run -d --rm --name "$NAME" --network "$net" -v "$REPO_DIR:/repo:ro" python:3.12-slim \
  python3 /repo/deploy/load/generate_load.py --target syslog --protocol tcp \
  --host shadowtracer-worker-test --port 5515 --rate "$RATE" --duration "$DURATION" \
  --run-id "${rid}-warm" >/dev/null
ok "warmup running in the background (container '$NAME')"
say "stop any time with: deploy/demo/demo-warmup.sh stop"
