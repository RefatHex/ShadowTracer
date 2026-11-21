#!/usr/bin/env bash
# Run-scoped throughput gate (Phase 7.x).
#
# Loads the kafka path at a fixed rate, then asserts the RUN's landed count equals delivered.
# The count is scoped to THIS run's keys (agent_id LIKE 'load-<run>-%' in ClickHouse, and the
# (node, alert_id) key-join into Postgres incident_alerts) - NOT a raw time window. A time-window
# count on a live lab also catches the normal-activity generator's benign memberships, which is
# exactly what made an earlier run read 12,001 memberships for 12,000 events (a measurement
# artifact, not a duplicate: incident_alerts_identity_unique already makes each alert exactly one
# membership; see test_replay_same_batch_twice_adds_no_memberships).
#
# Usage:  deploy/load/throughput_gate.sh [RATE] [DURATION_S] [SEED]
#   RETIME=1 deploy/load/throughput_gate.sh 100 120 42   # also measure alert->row latency
set -uo pipefail
cd "$(dirname "$0")/../.."                      # repo root
RATE=${1:-100}; DUR=${2:-120}; SEED=${3:-42}
set -a; . deploy/lab/.env; set +a
export KAFKA_SECURITY_PROTOCOL=SASL_SSL KAFKA_SASL_USERNAME=admin \
  KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD" KAFKA_SSL_CA_LOCATION="$PWD/deploy/lab/kafka-certs/ca.crt"
RUN=tput-$(date +%s)
DC="docker compose -f deploy/lab/docker-compose.yml"
chq(){ $DC exec -T ch-clickhouse-1 clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -q "$1" 2>/dev/null; }
pgq(){ $DC exec -T postgres psql -U shadowtracer -d shadowtracer -tAc "$1"; }
PGC=$($DC ps -q postgres)

echo "== load: rate=$RATE dur=${DUR}s seed=$SEED retime=${RETIME:-off} run=$RUN"
# Sample the OOM-relevant Postgres memory (non-reclaimable: cgroup anon + slab + shmem, where shmem
# is the pinned shared_buffers) through load + drain. docker-stats MemUsage / memory.current also
# count reclaimable PAGE CACHE of the data files, which Postgres fills toward the limit; the kernel
# reclaims it under pressure, so that is not an OOM risk (0 restarts even at the old 320m). anon +
# slab + shmem is the real working set the limit must hold.
MEMLOG=$(mktemp)
( for _ in $(seq 1 120); do
    docker exec "$PGC" awk '/^anon /{a=$2}/^slab /{s=$2}/^shmem /{h=$2}END{printf "%.1f\n",(a+s+h)/1048576}' /sys/fs/cgroup/memory.stat
    sleep 2
  done >"$MEMLOG" 2>/dev/null ) &
SAMPLER=$!

DELIVERED=$(PYTHONPATH=shadowtracer/ingest shadowtracer/ingest/.venv/bin/python deploy/load/generate_load.py \
  --target kafka --tenant-key "$TEST_TENANT_KEY" --run-id "$RUN" --rate "$RATE" --duration "$DUR" --seed "$SEED" \
  ${RETIME:+--retime} | tee /dev/stderr | sed -n 's/.*DONE seq=[0-9]* delivered=\([0-9]*\).*/\1/p')

# drain: wait until ClickHouse holds every run event (writer kept up)
START=$(date +%s); CH=0
for _ in $(seq 1 80); do
  CH=$(chq "SELECT count() FROM shadowtracer.events WHERE tenant_id='$TEST_TENANT_KEY' AND agent_id LIKE 'load-$RUN-%'")
  [ "$CH" = "$DELIVERED" ] && break; sleep 3
done
DRAIN=$(( $(date +%s) - START ))
kill "$SAMPLER" 2>/dev/null; wait "$SAMPLER" 2>/dev/null
PEAK=$(awk '{v=$1+0; if(v>m)m=v} END{printf "%.1f", m}' "$MEMLOG")
TOTAL=$(( $(docker exec "$PGC" cat /sys/fs/cgroup/memory.current) / 1048576 ))   # incl reclaimable cache

# run-scoped memberships: key-join the run's (node, alert_id) into incident_alerts
KEYS=$(mktemp); chq "SELECT DISTINCT cluster_node, alert_id FROM shadowtracer.events WHERE tenant_id='$TEST_TENANT_KEY' AND agent_id LIKE 'load-$RUN-%' FORMAT TSV" >"$KEYS"
$DC cp "$KEYS" postgres:/tmp/gate_keys.tsv >/dev/null
# \copy is a psql meta-command: it must be read from stdin/a script, not passed via -c.
PGM=$($DC exec -T postgres psql -U shadowtracer -d shadowtracer -tA <<SQL | grep -E '^[0-9]+$' | tail -1
CREATE TEMP TABLE k(node text, alert_id text);
\copy k FROM '/tmp/gate_keys.tsv'
SELECT count(*) FROM incident_alerts ia JOIN k ON k.node=ia.node AND k.alert_id=ia.alert_id WHERE ia.tenant_key='$TEST_TENANT_KEY';
SQL
)

DL=$(chq "SELECT count() FROM shadowtracer.dead_letter_events WHERE tenant_id='$TEST_TENANT_KEY' AND failed_at > now() - INTERVAL 20 MINUTE"); DL=${DL:-NA}
R=0; for s in writer-1 writer-2 correlate-1 correlate-2; do c=$($DC ps -q $s); R=$((R + $(docker inspect --format '{{.RestartCount}}' "$c") )); done
LAT=$(chq "SELECT concat(toString(round(quantile(0.5)(d))),' / ',toString(round(quantile(0.95)(d)))) FROM (SELECT dateDiff('millisecond', time, ingested_at) d FROM shadowtracer.events WHERE tenant_id='$TEST_TENANT_KEY' AND agent_id LIKE 'load-$RUN-%')")
LIMIT_MIB=$(( $(docker inspect --format '{{.HostConfig.Memory}}' "$PGC") / 1048576 ))
MARGIN=$(awk -v p="$PEAK" -v l="$LIMIT_MIB" 'BEGIN{printf "%.1f", (l-p)/l*100}')

echo "---- gate (run-scoped) ----"
echo "delivered        = $DELIVERED"
echo "clickhouse events= $CH   (expected == delivered)"
echo "pg memberships   = $PGM   (expected == delivered, key-join scoped)"
echo "drain            = ${DRAIN}s"
echo "dead letters     = $DL"
echo "restarts         = $R"
echo "pg peak rss      = ${PEAK} / ${LIMIT_MIB} MiB  anon+slab, OOM-relevant  (margin ${MARGIN}%)"
echo "pg total (cache) = ${TOTAL} / ${LIMIT_MIB} MiB  incl reclaimable page cache (not an OOM risk)"
echo "writer p50/p95 ms= $LAT   (meaningful only with RETIME=1)"
rm -f "$MEMLOG" "$KEYS"
if [ "$CH" = "$DELIVERED" ] && [ "$PGM" = "$DELIVERED" ] && [ "$DL" = "0" ] && [ "$R" = "0" ]; then
  echo "GATE PASS"; exit 0
else
  echo "GATE FAIL"; exit 1
fi
