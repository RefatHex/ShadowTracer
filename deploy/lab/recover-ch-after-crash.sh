#!/usr/bin/env bash
# Recovers ClickHouse partitions after an unclean host reset left 0-byte parts
# on both replicas (2026-11-04 power outage; docs/THROUGHPUT_BASELINE.md §11).
# Supported operations only, no Keeper edits:
#   - every non-broken copy of the affected partitions is gathered into scratch
#     tables: active rows on both replicas, the parts ClickHouse detached as
#     covered-by-broken/unexpected/ignored (ATTACH PART into a scratch table of
#     the same partition/sort key), the item-1 scratch copy, and - for
#     fingerprint_occurrences - the closer's own source of truth in Postgres;
#   - the distinct union (by each table's identity key) replaces the partition
#     via DROP PARTITION + INSERT, which also clears the unfetchable GET_PART
#     queue entries; events_hourly_rollup is rebuilt from the restored events
#     by its materialized view.
# Stops at the first failed check. Run from deploy/lab.
# DRY_RUN=1: only gather and report what would be restored (no pause, no
# DROP PARTITION, nothing replaced) - the scratch copies are kept either way.
# RESUME=1: keep the detached parts already attached into shadowtracer_recover
# (steps 2-3 take ~an hour on this lab) and continue from step 4.
set -euo pipefail
LOG=${LOG:-recover-ch-after-crash.$(date +%Y%m%d-%H%M%S).log}
exec > >(tee "$LOG") 2>&1
set -a; source .env; set +a

T=6da85d3ba8d9b0974ea6d3e712575eca
EV_PARTS=(7ee693fab4e147b89420fe7efeb01ceb 24a53b97a79eb024d642344517d0e891)  # (test tenant, 202610) / (test tenant, 202611)
FP_PART=202611
# The previous benchmark's rows (deleted by mutation 0000000119) must not come back from old copies.
OLD_BENCH="tenant_id = '$T' AND ingested_at >= '2026-11-03 21:40:00' AND ingested_at < '2026-11-04 08:43:00'"
OLD_BENCH_FP="tenant_id = '$T' AND closed_at >= '2026-11-03 21:40:00' AND closed_at < '2026-11-04 08:43:00'"
# Load-generator rows (deploy/load tags every event with load-<run>) in these
# test-tenant partitions are NOT carried over: disposable benchmark data, and
# millions of rows after the 2026-11-04 reruns - far beyond what a scratch
# copy fits in this lab's ClickHouse memory. Everything else is kept.
LOAD="tenant_id = '$T' AND (agent_id LIKE 'load-%' OR actor_user LIKE 'load-%' OR target_user LIKE 'load-%' OR position(message, 'load-') > 0)"
N1=shadowtracer-lab-ch-clickhouse-1-1
N2=shadowtracer-lab-ch-clickhouse-2-1
q()  { docker exec "$1" clickhouse-client --max_threads=1 --max_block_size=8192 --max_insert_threads=1 --min_insert_block_size_rows=65536 --min_insert_block_size_bytes=16777216 --insert_deduplicate=0 --replication_alter_partitions_sync=2 --mutations_sync=2 --query "$2"; }
q1() { q "$N1" "$1"; }
check() { if [ "$2" != "$3" ]; then echo "CHECK FAILED: $1: expected [$2] got [$3]"; exit 1; fi; echo "ok: $1 = $3"; }
in_list() { local IFS=,; echo "'${*}'" | sed "s/,/','/g"; }
EVP=$(in_list "${EV_PARTS[@]}")
NULLSAFE="count(), sum(cityHash64(toString(tuple(*))))"

PAUSE=(shadowtracer-lab-shipper-worker-test-1 shadowtracer-lab-writer-1-1 shadowtracer-lab-writer-2-1
       shadowtracer-lab-closer-1-1 shadowtracer-lab-closer-2-1)

echo "== 0. before: stuck GET_PART entries must all be inside the partitions this replaces"
for n in $N1 $N2; do
  q $n "SELECT '$n', table, splitByChar('_', new_part_name)[1] p, count() FROM system.replication_queue WHERE database='shadowtracer' AND type='GET_PART' GROUP BY table, p ORDER BY table FORMAT TSV"
  check "GET_PART entries outside the planned partitions on $n" 0 "$(q $n "SELECT count() FROM system.replication_queue WHERE database='shadowtracer' AND type='GET_PART' AND NOT ((table IN ('events','events_hourly_rollup') AND splitByChar('_', new_part_name)[1] IN ($EVP)) OR (table='fingerprint_occurrences' AND splitByChar('_', new_part_name)[1]='$FP_PART'))")"
done

DRY_RUN=${DRY_RUN:-0}
if [ "$DRY_RUN" != 1 ]; then
  echo "== 1. pause the services that write into these partitions (test-tenant events, fingerprints)"
  docker stop "${PAUSE[@]}" >/dev/null
  trap 'echo "== restarting paused services"; docker start "${PAUSE[@]}" >/dev/null' EXIT
fi

RESUME=${RESUME:-0}
if [ "$RESUME" = 1 ]; then
  echo "== 2-3. resuming: keeping the detached parts already in shadowtracer_recover"
  for n in $N1 $N2; do q $n "SELECT '$n', table, count(), sum(rows) FROM system.parts WHERE database='shadowtracer_recover' AND active GROUP BY table FORMAT TSV"; done
  q1 "DROP TABLE IF EXISTS shadowtracer_recover.events_final SYNC"
  q1 "DROP TABLE IF EXISTS shadowtracer_recover.fp_final SYNC"
else
echo "== 2. scratch tables with the real partition/sort keys, on both nodes"
for n in $N1 $N2; do
  [ "$(q $n "EXISTS DATABASE shadowtracer_recover")" = 0 ] || q $n "DROP DATABASE shadowtracer_recover SYNC"
  q $n "CREATE DATABASE shadowtracer_recover"
  q $n "CREATE TABLE shadowtracer_recover.events AS shadowtracer.events ENGINE = ReplacingMergeTree(ingested_at) PARTITION BY (tenant_id, toYYYYMM(time)) ORDER BY (tenant_id, time, cluster_node, alert_id)"
  q $n "CREATE TABLE shadowtracer_recover.fingerprint_occurrences AS shadowtracer.fingerprint_occurrences ENGINE = MergeTree PARTITION BY toYYYYMM(closed_at) ORDER BY (tenant_id, fingerprint_key, incident_id)"
done

echo "== 3. attach each node's detached non-broken parts of the affected partitions into its scratch"
attach_detached() { # node table partitions...
  local n=$1 t=$2; shift 2
  local src dst
  src=$(q $n "SELECT data_paths[1] FROM system.tables WHERE database='shadowtracer' AND name='$t'")detached
  dst=$(q $n "SELECT data_paths[1] FROM system.tables WHERE database='shadowtracer_recover' AND name='$t'")detached
  local ok=0 bad=0
  for p in "$@"; do
    for name in $(q $n "SELECT name FROM system.detached_parts WHERE database='shadowtracer' AND table='$t' AND partition_id='$p' AND reason IN ('covered-by-broken','unexpected','ignored') FORMAT TSV"); do
      local reason; reason=$(q $n "SELECT reason FROM system.detached_parts WHERE database='shadowtracer' AND table='$t' AND name='$name'")
      local part=${name#"${reason}_"}
      docker exec "$n" bash -c "cp -a '$src/$name' '$dst/$part' && chown -R clickhouse:clickhouse '$dst/$part'"
      if q $n "ALTER TABLE shadowtracer_recover.$t ATTACH PART '$part'" >/dev/null 2>&1; then ok=$((ok+1)); else bad=$((bad+1)); docker exec "$n" rm -rf "$dst/$part"; fi
    done
  done
  echo "$n $t: attached $ok detached parts, skipped $bad unreadable"
}
for n in $N1 $N2; do
  attach_detached $n events "${EV_PARTS[@]}"
  attach_detached $n fingerprint_occurrences $FP_PART
done

fi

echo "== 4. add the active rows of both replicas, the item-1 scratch copy, and (fingerprints) Postgres"
for n in $N1 $N2; do
  q $n "INSERT INTO shadowtracer_recover.events SELECT * FROM shadowtracer.events WHERE _partition_id IN ($EVP) AND NOT ($LOAD)"
  q $n "INSERT INTO shadowtracer_recover.fingerprint_occurrences SELECT * FROM shadowtracer.fingerprint_occurrences WHERE _partition_id = '$FP_PART'"
done
for t in events fingerprint_occurrences; do  # node 2's scratch -> node 1, Native format over a pipe
  docker exec $N2 clickhouse-client --query "SELECT * FROM shadowtracer_recover.$t FORMAT Native" \
    | docker exec -i $N1 clickhouse-client --query "INSERT INTO shadowtracer_recover.$t FORMAT Native"
done
if [ "$(q1 "EXISTS TABLE shadowtracer_repair.events")" = 1 ]; then
  q1 "INSERT INTO shadowtracer_recover.events SELECT * FROM shadowtracer_repair.events WHERE _partition_id IN ($EVP) AND NOT ($LOAD)"
  q1 "INSERT INTO shadowtracer_recover.fingerprint_occurrences SELECT * FROM shadowtracer_repair.fingerprint_occurrences"
fi
docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAF $'\t' -c \
  "SELECT tenant_key, fingerprint_key, id, to_char(closed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.MS'), alert_count FROM incidents WHERE state='closed' AND fingerprint_key IS NOT NULL AND closed_at >= '2026-11-01 00:00:00+00' AND closed_at < '2026-12-01 00:00:00+00'" \
  | docker exec -i $N1 clickhouse-client --query "INSERT INTO shadowtracer_recover.fingerprint_occurrences (tenant_id, fingerprint_key, incident_id, closed_at, alert_count) FORMAT TSV"

echo "== 5. distinct union per identity key (old benchmark rows excluded)"
q1 "CREATE TABLE shadowtracer_recover.events_final AS shadowtracer.events ENGINE = MergeTree ORDER BY tuple()"
q1 "INSERT INTO shadowtracer_recover.events_final SELECT * FROM shadowtracer_recover.events WHERE _partition_id IN ($EVP) AND NOT ($OLD_BENCH) AND NOT ($LOAD) ORDER BY ingested_at DESC LIMIT 1 BY tenant_id, time, cluster_node, alert_id"
q1 "CREATE TABLE shadowtracer_recover.fp_final AS shadowtracer.fingerprint_occurrences ENGINE = MergeTree ORDER BY tuple()"
q1 "INSERT INTO shadowtracer_recover.fp_final SELECT * FROM shadowtracer_recover.fingerprint_occurrences WHERE toYYYYMM(closed_at) = $FP_PART AND NOT ($OLD_BENCH_FP) ORDER BY closed_at LIMIT 1 BY tenant_id, fingerprint_key, incident_id"
for p in "${EV_PARTS[@]}"; do
  echo "events $p: active node1 $(q $N1 "SELECT count() FROM shadowtracer.events WHERE _partition_id='$p'") / node2 $(q $N2 "SELECT count() FROM shadowtracer.events WHERE _partition_id='$p'") -> recovered distinct $(q1 "SELECT count() FROM shadowtracer_recover.events_final WHERE (tenant_id, toYYYYMM(time)) IN (SELECT tenant_id, toYYYYMM(time) FROM shadowtracer.events WHERE _partition_id='$p' LIMIT 1) ")"
done
echo "fingerprints $FP_PART: active node1 $(q $N1 "SELECT count() FROM shadowtracer.fingerprint_occurrences WHERE _partition_id='$FP_PART'") / node2 $(q $N2 "SELECT count() FROM shadowtracer.fingerprint_occurrences WHERE _partition_id='$FP_PART'") -> recovered distinct $(q1 "SELECT count() FROM shadowtracer_recover.fp_final")"
EV_SUM=$(q1 "SELECT $NULLSAFE FROM shadowtracer_recover.events_final FORMAT TSV")
FP_SUM=$(q1 "SELECT $NULLSAFE FROM shadowtracer_recover.fp_final FORMAT TSV")
check "recovered events contain no old-benchmark rows" 0 "$(q1 "SELECT count() FROM shadowtracer_recover.events_final WHERE $OLD_BENCH")"
[ "$(cut -f1 <<<"$EV_SUM")" -gt 0 ] || { echo "CHECK FAILED: no events recovered"; exit 1; }
if [ "$DRY_RUN" = 1 ]; then echo "DRY RUN done - nothing replaced; scratch in shadowtracer_recover"; exit 0; fi

echo "== 6. replace the partitions; re-insert right after each drop, check the queue only afterwards"
for p in "${EV_PARTS[@]}"; do
  q1 "ALTER TABLE shadowtracer.events_hourly_rollup DROP PARTITION ID '$p'"
  q1 "ALTER TABLE shadowtracer.events DROP PARTITION ID '$p'"
done
q1 "INSERT INTO shadowtracer.events SELECT * FROM shadowtracer_recover.events_final"   # MV rebuilds the rollup
q1 "ALTER TABLE shadowtracer.fingerprint_occurrences DROP PARTITION ID '$FP_PART'"
q1 "INSERT INTO shadowtracer.fingerprint_occurrences SELECT * FROM shadowtracer_recover.fp_final"
for n in $N1 $N2; do for t in events events_hourly_rollup fingerprint_occurrences; do q $n "SYSTEM SYNC REPLICA shadowtracer.$t"; done; done
for i in $(seq 1 30); do
  left=$(( $(q $N1 "SELECT count() FROM system.replication_queue WHERE database='shadowtracer' AND type='GET_PART'") + $(q $N2 "SELECT count() FROM system.replication_queue WHERE database='shadowtracer' AND type='GET_PART'") ))
  [ "$left" = 0 ] && break; sleep 2
done
check "GET_PART queue entries (both nodes)" 0 "$left"

echo "== 7. verify"
for n in $N1 $N2; do
  check "events restored on $n" "$EV_SUM" "$(q $n "SELECT $NULLSAFE FROM shadowtracer.events WHERE _partition_id IN ($EVP) FORMAT TSV")"
  check "fingerprints restored on $n" "$FP_SUM" "$(q $n "SELECT $NULLSAFE FROM shadowtracer.fingerprint_occurrences WHERE _partition_id = '$FP_PART' FORMAT TSV")"
done
P="SELECT groupArray((_partition_id, c, h)) FROM (SELECT _partition_id, count() c, sum(cityHash64(toString(tuple(*)))) h FROM shadowtracer.%s GROUP BY _partition_id ORDER BY _partition_id)"
for t in events fingerprint_occurrences dead_letter_events sequence_firings; do
  check "$t node1 == node2" "$(q $N1 "$(printf "$P" $t)")" "$(q $N2 "$(printf "$P" $t)")"
done
R="SELECT count(), sum(cityHash64(tenant_id, hour, agent_id, agent_name, rule_id, rule_level, c)) FROM (SELECT tenant_id, hour, agent_id, agent_name, rule_id, rule_level, uniqExactMerge(identity_state) c FROM shadowtracer.events_hourly_rollup GROUP BY ALL) FORMAT TSV"
check "events_hourly_rollup finalized node1 == node2" "$(q $N1 "$R")" "$(q $N2 "$R")"
b=$(q1 "SELECT (SELECT uniqExactMerge(identity_state) FROM shadowtracer.events_hourly_rollup WHERE tenant_id='$T' AND toYYYYMM(hour) IN (202610, 202611)), (SELECT uniqExact(cluster_node, alert_id) FROM shadowtracer.events WHERE tenant_id='$T' AND toYYYYMM(time) IN (202610, 202611)) FORMAT TSV")
check "rebuilt test-tenant rollup identities == base identities (2026-10/11)" "$(cut -f2 <<<"$b")" "$(cut -f1 <<<"$b")"
for n in $N1 $N2; do
  check "old benchmark events on $n" 0 "$(q $n "SELECT count() FROM shadowtracer.events WHERE $OLD_BENCH")"
  check "old benchmark fingerprints on $n" 0 "$(q $n "SELECT count() FROM shadowtracer.fingerprint_occurrences WHERE $OLD_BENCH_FP")"
  check "load-* rollup rows from the old benchmark on $n" 0 "$(q $n "SELECT count() FROM shadowtracer.events_hourly_rollup WHERE tenant_id='$T' AND agent_id LIKE 'load-s%'")"
  q $n "SELECT '$n queue', count() FROM system.replication_queue WHERE database='shadowtracer' FORMAT TSV"
done
echo "RECOVERY OK - scratch kept in shadowtracer_recover on both nodes"
