#!/usr/bin/env bash
# Many syslog devices at once: N generator containers on the lab network, each
# with its own IP, so the manager sees N distinct senders (`location` = the
# sender IP) instead of the one a single host-side generator gives.
# usage: syslog_fleet.sh <devices> <total_rate> <duration_s> <run_id> [manager_ip]
set -euo pipefail
N=$1 RATE=$2 DUR=$3 RUN=$4
MANAGER=${5:-$(docker inspect shadowtracer-lab-shadowtracer-worker-test-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')}
NETWORK=${NETWORK:-shadowtracer-lab_lab}
LOAD_DIR=$(cd "$(dirname "$0")" && pwd)
PER=$(( RATE / N ))
[ "$PER" -ge 1 ] || { echo "total_rate must be >= devices" >&2; exit 2; }
names=()
for i in $(seq 1 "$N"); do
  name="loadgen-$RUN-$i"
  names+=("$name")
  docker run -d --rm --name "$name" --network "$NETWORK" -v "$LOAD_DIR:/load:ro" --entrypoint python \
    shadowtracer-lab/ingest:local /load/generate_load.py --target syslog --host "$MANAGER" --port 5514 \
    --run-id "$RUN-d$i" --rate "$PER" --duration "$DUR" >/dev/null
done
echo "$N devices x $PER/s = $(( N * PER ))/s for ${DUR}s -> $MANAGER:5514"
docker wait "${names[@]}" >/dev/null 2>&1 || true
echo "fleet done"
