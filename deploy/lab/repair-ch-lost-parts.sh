#!/usr/bin/env bash
# One-off repair for the 2026-11-02 lost-part replication stall (see
# docs/THROUGHPUT_BASELINE.md §7.9 for the investigation). Supported SQL only:
# copy each affected partition to a scratch table, verify, DROP PARTITION (which
# removes the unfetchable GET_PART queue entries for that range on both
# replicas), re-insert, verify both replicas, then apply the queued benchmark
# cleanup. No Keeper edits. Stops at the first failed check. Run from deploy/lab.
set -euo pipefail
# Needs both replicas: the "ha" compose profile (6.1c follow-up).
if ! docker ps -q -f name=^shadowtracer-lab-ch-clickhouse-2-1$ -f status=running | grep -q .; then
    echo "ch-clickhouse-2 is not running: start the ha profile first: ./ha.sh up (./ha.sh down afterwards)"
    exit 2
fi
# R7: ti-sync and ti-matcher stay stopped while "ha" runs (memory cap); ./ha.sh down restarts them.
docker compose stop ti-sync ti-matcher >/dev/null 2>&1 || true
LOG=${LOG:-repair-ch-lost-parts.$(date +%Y%m%d-%H%M%S).log}
exec > >(tee "$LOG") 2>&1

T=6da85d3ba8d9b0974ea6d3e712575eca   # test tenant (benchmark cleanup only)
EV_PARTS="'24a53b97a79eb024d642344517d0e891','a9b80bea156a07dfae58e664f2664874'"
N1=shadowtracer-lab-ch-clickhouse-1-1
N2=shadowtracer-lab-ch-clickhouse-2-1
q()  { docker exec "$1" clickhouse-client --max_threads=2 --insert_deduplicate=0 --replication_alter_partitions_sync=2 --mutations_sync=2 --query "$2"; }
q1() { q "$N1" "$1"; }
check() { # label, expected, actual
  if [ "$2" != "$3" ]; then echo "CHECK FAILED: $1: expected [$2] got [$3]"; exit 1; fi
  echo "ok: $1 = $3"
}

WRITERS=(shadowtracer-lab-shipper-worker-test-1 shadowtracer-lab-shipper-worker1-1 shadowtracer-lab-shipper-worker2-1
         shadowtracer-lab-closer-1-1 shadowtracer-lab-closer-2-1 shadowtracer-lab-writer-1-1 shadowtracer-lab-writer-2-1
         shadowtracer-lab-correlate-1-1 shadowtracer-lab-correlate-2-1
         shadowtracer-lab-console-backend-1-1 shadowtracer-lab-console-backend-2-1)

echo "== 0. before"
for n in $N1 $N2; do q $n "SELECT '$n', table, new_part_name, num_tries FROM system.replication_queue WHERE database='shadowtracer' ORDER BY table FORMAT TSV"; done
q1 "SELECT table, mutation_id, parts_to_do FROM system.mutations WHERE database='shadowtracer' AND NOT is_done FORMAT TSV"

echo "== 1. pause every service that writes to ClickHouse (Kafka/alerts.json buffer meanwhile)"
docker stop "${WRITERS[@]}" >/dev/null
trap 'echo "== restarting paused services"; docker start "${WRITERS[@]}" >/dev/null' EXIT

echo "== 2. copy affected partitions to scratch (node 1; node 1 holds the 4 fingerprint rows node 2 lost)"
q1 "DROP DATABASE IF EXISTS shadowtracer_repair SYNC"
q1 "CREATE DATABASE shadowtracer_repair"
for t in events fingerprint_occurrences dead_letter_events; do
  q1 "CREATE TABLE shadowtracer_repair.$t AS shadowtracer.$t ENGINE = MergeTree ORDER BY tuple()"
done
q1 "INSERT INTO shadowtracer_repair.events SELECT * FROM shadowtracer.events WHERE _partition_id IN ($EV_PARTS)"
q1 "INSERT INTO shadowtracer_repair.fingerprint_occurrences SELECT * FROM shadowtracer.fingerprint_occurrences WHERE _partition_id = '202611'"
q1 "INSERT INTO shadowtracer_repair.dead_letter_events SELECT * FROM shadowtracer.dead_letter_events WHERE _partition_id = '202611'"

declare -A WHERE=( [events]="_partition_id IN ($EV_PARTS)" [fingerprint_occurrences]="_partition_id = '202611'" [dead_letter_events]="_partition_id = '202611'" )
declare -A SUM
for t in events fingerprint_occurrences dead_letter_events; do
  src=$(q1 "SELECT count(), sum(cityHash64(*)) FROM shadowtracer.$t WHERE ${WHERE[$t]} FORMAT TSV")
  cpy=$(q1 "SELECT count(), sum(cityHash64(*)) FROM shadowtracer_repair.$t FORMAT TSV")
  check "copy of $t (rows, checksum)" "$src" "$cpy"
  SUM[$t]=$cpy
done

echo "== 3. drop the affected partitions (replicated; waits for both replicas)"
for p in 24a53b97a79eb024d642344517d0e891 a9b80bea156a07dfae58e664f2664874; do
  q1 "ALTER TABLE shadowtracer.events DROP PARTITION ID '$p'"
  q1 "ALTER TABLE shadowtracer.events_hourly_rollup DROP PARTITION ID '$p'"
done
q1 "ALTER TABLE shadowtracer.fingerprint_occurrences DROP PARTITION ID '202611'"
q1 "ALTER TABLE shadowtracer.dead_letter_events DROP PARTITION ID '202611'"

echo "== 4. queue and mutations must clear"
for _ in $(seq 1 30); do
  left=$(( $(q $N1 "SELECT count() FROM system.replication_queue WHERE database='shadowtracer'") + $(q $N2 "SELECT count() FROM system.replication_queue WHERE database='shadowtracer'") ))
  muts=$(q1 "SELECT count() FROM system.mutations WHERE database='shadowtracer' AND NOT is_done")
  [ "$left" = 0 ] && [ "$muts" = 0 ] && break
  sleep 2
done
check "replication_queue entries (both nodes)" 0 "$left"
check "unfinished mutations" 0 "$muts"

echo "== 5. re-insert (dedup off so no block is mistaken for an earlier insert; MV rebuilds the rollup)"
q1 "INSERT INTO shadowtracer.events SELECT * FROM shadowtracer_repair.events"
q1 "INSERT INTO shadowtracer.fingerprint_occurrences SELECT * FROM shadowtracer_repair.fingerprint_occurrences"
q1 "INSERT INTO shadowtracer.dead_letter_events SELECT * FROM shadowtracer_repair.dead_letter_events"
for n in $N1 $N2; do q $n "SYSTEM SYNC REPLICA shadowtracer.events"; q $n "SYSTEM SYNC REPLICA shadowtracer.events_hourly_rollup"; q $n "SYSTEM SYNC REPLICA shadowtracer.fingerprint_occurrences"; q $n "SYSTEM SYNC REPLICA shadowtracer.dead_letter_events"; done
for t in events fingerprint_occurrences dead_letter_events; do
  for n in $N1 $N2; do
    check "$t restored on $n (rows, checksum)" "${SUM[$t]}" "$(q $n "SELECT count(), sum(cityHash64(*)) FROM shadowtracer.$t WHERE ${WHERE[$t]} FORMAT TSV")"
  done
done

echo "== 6. replicas must now agree on every table (rows + checksum per partition; rollup compared finalized)"
for t in events fingerprint_occurrences dead_letter_events sequence_firings; do
  check "$t node1 == node2" "$(q $N1 "SELECT groupArray((_partition_id, c, h)) FROM (SELECT _partition_id, count() c, sum(cityHash64(*)) h FROM shadowtracer.$t GROUP BY _partition_id ORDER BY _partition_id)")" \
                            "$(q $N2 "SELECT groupArray((_partition_id, c, h)) FROM (SELECT _partition_id, count() c, sum(cityHash64(*)) h FROM shadowtracer.$t GROUP BY _partition_id ORDER BY _partition_id)")"
done
R="SELECT count(), sum(cityHash64(tenant_id, hour, agent_id, agent_name, rule_id, rule_level, c)) FROM (SELECT tenant_id, hour, agent_id, agent_name, rule_id, rule_level, uniqExactMerge(identity_state) c FROM shadowtracer.events_hourly_rollup GROUP BY ALL) FORMAT TSV"
check "events_hourly_rollup finalized node1 == node2" "$(q $N1 "$R")" "$(q $N2 "$R")"

echo "== 7. queued benchmark cleanup (test tenant, created after 2026-11-03 21:40 UTC)"
q1 "ALTER TABLE shadowtracer.fingerprint_occurrences DELETE WHERE tenant_id='$T' AND closed_at >= '2026-11-03 21:40:00'"
q1 "ALTER TABLE shadowtracer.events_hourly_rollup DELETE WHERE tenant_id='$T' AND agent_id LIKE 'load-%'"
for n in $N1 $N2; do
  check "benchmark events rows on $n" 0 "$(q $n "SELECT count() FROM shadowtracer.events WHERE tenant_id='$T' AND ingested_at >= '2026-11-03 21:40:00'")"
  check "benchmark fingerprint rows on $n" 0 "$(q $n "SELECT count() FROM shadowtracer.fingerprint_occurrences WHERE tenant_id='$T' AND closed_at >= '2026-11-03 21:40:00'")"
  check "load-* rollup rows on $n" 0 "$(q $n "SELECT count() FROM shadowtracer.events_hourly_rollup WHERE tenant_id='$T' AND agent_id LIKE 'load-%'")"
done
B="SELECT (SELECT uniqExactMerge(identity_state) FROM shadowtracer.events_hourly_rollup WHERE tenant_id='$T'), (SELECT uniqExact(cluster_node, alert_id) FROM shadowtracer.events WHERE tenant_id='$T') FORMAT TSV"
b=$(q1 "$B"); check "test-tenant rollup identities == base identities" "$(cut -f2 <<<"$b")" "$(cut -f1 <<<"$b")"

echo "== 8. after"
for n in $N1 $N2; do q $n "SELECT '$n', count() FROM system.replication_queue WHERE database='shadowtracer' FORMAT TSV"; done
q1 "SELECT count() FROM system.mutations WHERE database='shadowtracer' AND NOT is_done"
echo "REPAIR OK - scratch copy kept in shadowtracer_repair on node 1 until you drop it"
