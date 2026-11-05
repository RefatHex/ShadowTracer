#!/usr/bin/env bash
# Throughput baseline, end-to-end step: raw sshd syslog -> test manager
# (analysisd) -> shipper -> Kafka -> writer + correlator, at one fixed rate.
# Prints lag trend (sample_pipeline.py), per-container CPU/RAM, e2e latency
# percentiles, disk growth, dead letters, error log lines and restarts.
# usage (from deploy/lab): ../load/e2e_step.sh <rate> <seconds> <run_id> [devices] [agent_pct]
#   devices    >0: the syslog part comes from that many devices (syslog_fleet.sh),
#              not one host-side sender
#   agent_pct  share of <rate> sent as alerts from AGENTS (default 200) simulated
#              agents, produced straight to the tenant topic keyed by agent.id (the
#              shipper's key for real agents); the rest is raw syslog through
#              analysisd. Never append to the manager's alerts.json: analysisd
#              is its only writer and flushes through stdio, so a second writer
#              splits its lines and every broken line is a dead letter.
# Latency is measured on the syslog part (agent 000, real analysisd timestamps).
set -u
RATE=$1 DUR=$2 RUN=$3 DEVICES=${4:-0} AGENT_PCT=${5:-0} AGENTS=${AGENTS:-200}
AGENT_RATE=$(( RATE * AGENT_PCT / 100 )); SYSLOG_RATE=$(( RATE - AGENT_RATE ))
TENANT=${TEST_TENANT_KEY:-6da85d3ba8d9b0974ea6d3e712575eca}
MANAGER_IP=$(docker inspect shadowtracer-lab-shadowtracer-worker-test-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
set -a; source .env; set +a
export KAFKA_SECURITY_PROTOCOL=SASL_SSL KAFKA_SASL_USERNAME=admin KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD" KAFKA_SSL_CA_LOCATION="$PWD/kafka-certs/ca.crt"
PY=../../shadowtracer/correlate/.venv/bin/python3
CH="docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client --query"
PSQL="docker exec shadowtracer-lab-postgres-1 env PGPASSWORD=$POSTGRES_PASSWORD psql -U $POSTGRES_USER -d $POSTGRES_DB -tAc"
PIPE="shadowtracer-lab-(shadowtracer-worker-test|shipper-worker-test|writer|correlate|kafka|ch-|postgres)"

disk() {
  echo "alerts_dir_bytes=$(du -sb alerts-worker-test | cut -f1)" \
       "kafka_bytes=$(docker exec shadowtracer-lab-kafka-1 du -sb /var/lib/kafka/data | cut -f1)" \
       "ch_events_bytes=$($CH "SELECT sum(bytes_on_disk) FROM system.parts WHERE database='shadowtracer' AND table='events' AND active")" \
       "pg_bytes=$($PSQL 'SELECT pg_database_size(current_database())')"
}
restarts() { docker ps --format '{{.Names}}' | grep -E "$PIPE" | sort | xargs docker inspect --format '{{.Name}} restarts={{.RestartCount}} started={{.State.StartedAt}}'; }

echo "### step rate=$RATE dur=${DUR}s run_id=$RUN syslog=$SYSLOG_RATE/s devices=$DEVICES agents=$AGENT_RATE/s over $AGENTS agents"
echo "--- disk before"; disk
echo "--- containers before"; restarts
START=$(date -u +'%F %T.%3N'); START_LOCAL=$(date +%FT%T)
$PY ../load/sample_pipeline.py --tenant-key "$TENANT" --interval 30 --duration $((DUR + 60)) &
SP=$!
(for _ in 1 2 3; do sleep $((DUR / 4)); echo "--- docker stats @$(date +%T)"; docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' | grep -E "$PIPE"; done) &
if [ "$AGENT_RATE" -gt 0 ]; then
  $PY ../load/generate_load.py --target kafka --tenant-key "$TENANT" --run-id "$RUN-ag" \
    --agents "$AGENTS" --rate "$AGENT_RATE" --duration "$DUR" > "/tmp/e2e-$RUN-agents.log" 2>&1 &
  AP=$!
fi
if [ "$DEVICES" -gt 0 ]; then
  ../load/syslog_fleet.sh "$DEVICES" "$SYSLOG_RATE" "$DUR" "$RUN" "$MANAGER_IP"
else
  $PY ../load/generate_load.py --target syslog --host "$MANAGER_IP" --port 5514 --run-id "$RUN" --rate "$SYSLOG_RATE" --duration "$DUR" | tail -1
fi
[ "$AGENT_RATE" -gt 0 ] && wait $AP && echo "agents: $(tail -1 /tmp/e2e-$RUN-agents.log)"
END=$(date -u +'%F %T.%3N')
wait $SP
echo "--- disk after"; disk
echo "--- containers after"; restarts
echo "--- writer latency: alert time -> ClickHouse row (ingested_at), ms, alerts generated during the step"
$CH "SELECT count() rows, round(quantile(0.5)(d)) p50, round(quantile(0.95)(d)) p95, round(quantile(0.99)(d)) p99, max(d) max FROM (SELECT dateDiff('millisecond', time, ingested_at) d FROM shadowtracer.events WHERE tenant_id='$TENANT' AND agent_id='000' AND time BETWEEN toDateTime64('$START',3,'UTC') AND toDateTime64('$END',3,'UTC')) FORMAT PrettyCompactNoEscapes"
echo "--- correlator latency: alert time -> incident_alerts.created_at, ms"
$PSQL "SELECT count(*), round(percentile_cont(0.5) WITHIN GROUP (ORDER BY d)), round(percentile_cont(0.95) WITHIN GROUP (ORDER BY d)), round(percentile_cont(0.99) WITHIN GROUP (ORDER BY d)), round(max(d)) FROM (SELECT extract(epoch FROM created_at - alert_time)*1000 d FROM incident_alerts WHERE tenant_key='$TENANT' AND alert_time BETWEEN '$START+00' AND '$END+00') x"
echo "--- dead letters for test tenant during step"
$CH "SELECT component, count() FROM shadowtracer.dead_letter_events WHERE tenant_id='$TENANT' AND failed_at >= toDateTime64('$START',3,'UTC') GROUP BY component FORMAT TSV"
echo "--- error/exception log lines during step"
for c in shipper-worker-test-1 writer-1-1 writer-2-1 correlate-1-1 correlate-2-1; do
  echo "$c $(docker logs --since "$START_LOCAL" shadowtracer-lab-$c 2>&1 | grep -ciE 'error|exception|traceback')"
done
