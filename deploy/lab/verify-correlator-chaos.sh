#!/usr/bin/env bash
# Phase 5A hardening, round 2: the first version of this script picked a
# fresh agent, looked up its partition's current owner from a
# `kafka-consumer-groups.sh --describe` snapshot, and killed that
# container - correct, but only ever exercised whichever container a
# `date +%s`-seeded agent id happened to hash to (both runs so far landed
# on correlate-2 by chance), and never proved the kill landed mid-stream
# rather than between two separately-flushed batches, and never measured
# how long recovery actually took.
#
# This version:
#   1. Deliberately searches for an agent id whose partition is owned by
#      a CHOSEN target container (never guessed/hardcoded - each
#      candidate agent id is tried by producing one REAL alert for it and
#      reading the partition confluent_kafka's producer actually assigned
#      it, off the delivery report; the real, current owner is then read
#      from a real `kafka-consumer-groups.sh --describe` of
#      shadowtracer-correlate, the correlator's own group - read from
#      docker-compose.yml's x-correlate-env KAFKA_GROUP_ID, never
#      guessed). Runs the full cycle once targeting correlate-1 and once
#      targeting correlate-2, so both get killed-as-owner at least once,
#      not by luck.
#   2. Produces a single continuous steady-rate stream of alerts and
#      issues `docker kill` on the real owner partway through it, with no
#      pause in production - not two separately-flushed batches.
#   3. Times T_kill (when docker kill was issued) against T_resume (the
#      first moment the incident's alert_count, queried directly from
#      Postgres on the same clock, exceeds its value at T_kill) and
#      reports failover = T_resume - T_kill, 3 times.
#   4. Scrapes the SURVIVOR's own /metrics (alerts_duplicate - the exact
#      counter consumer.py increments on the idempotency path) before and
#      after each run, for a REAL redelivery-dedup count - never invented;
#      if the scrape fails for any reason, says so and skips the number
#      rather than guessing at it.
#
# Run from deploy/lab/: ./verify-correlator-chaos.sh
set -uo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

GROUP=shadowtracer-correlate
TOPIC=shadowtracer.events.raw
KAFKA_BOOTSTRAP=127.0.0.1:9094
PY="../../shadowtracer/correlate/.venv/bin/python3"

C1_IP=172.28.0.42   # correlate-1 (docker-compose.yml's correlate-1 service ipv4_address)
C2_IP=172.28.0.43   # correlate-2 (docker-compose.yml's correlate-2 service ipv4_address)
C1_NAME=shadowtracer-lab-correlate-1-1
C2_NAME=shadowtracer-lab-correlate-2-1

N_STREAM=19     # alerts produced in the main steady-rate stream (plus 1 probe alert = 20 total)
KILL_AFTER=8    # index WITHIN the stream (of N_STREAM) at which docker kill is issued
RATE_HZ=5       # steady production rate - no pause for the kill

fail=0
failover_times=()
check() {
    local desc="$1" cmd="$2"
    if eval "$cmd"; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        fail=1
    fi
}

describe_group() {
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server localhost:9092 --describe --group "$GROUP"
}

owner_of_partition() {
    # $1 = partition number, $2 = a `describe_group` output to read from.
    # Column layout: GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET
    # LAG CONSUMER-ID HOST CLIENT-ID. HOST prints as /x.x.x.x.
    echo "$2" | awk -v p="$1" '$3 == p { print $8 }' | head -1 | tr -d '/'
}

psql_query() {
    docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$1"
}

scrape_metrics() {
    # $1 = container name. Prints the JSON metrics body, or nothing (and
    # a warning to stderr) if the scrape fails - never invents a value.
    docker exec "$1" python3 -c "
import urllib.request
try:
    print(urllib.request.urlopen('http://localhost:9104', timeout=3).read().decode())
except Exception as exc:
    import sys; print(f'SCRAPE_FAILED: {exc}', file=sys.stderr)
" 2>/dev/null
}

produce_probe() {
    # $1 = agent id. Produces one real alert for it and prints the
    # partition confluent_kafka's producer actually assigned it to -
    # read off the real delivery report, never computed/guessed locally.
    "$PY" - "$KAFKA_BOOTSTRAP" "$TENANT_KEY" "$1" <<'PYEOF'
import json, sys, time
from confluent_kafka import Producer

bootstrap, tenant, agent = sys.argv[1], sys.argv[2], sys.argv[3]

def alert(alert_id):
    return json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
        "id": alert_id,
        "rule": {"id": "5710", "level": 5, "description": "sshd authentication failure", "groups": ["sshd", "authentication_failed"]},
        "agent": {"id": agent, "name": agent, "ip": "172.28.0.99"},
        "manager": {"name": "wazuh-worker1"},
        "cluster": {"node": "worker1"},
        "data": {"srcip": "203.0.113.77"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": "Failed password for invalid user root from 203.0.113.77 port 51000 ssh2",
    })

producer = Producer({"bootstrap.servers": bootstrap})
key = f"{tenant}:{agent}".encode()
result = {}

def on_delivery(err, msg):
    if err is None:
        result["partition"] = msg.partition()

producer.produce("shadowtracer.events.raw", key=key, value=alert(f"{agent}.probe").encode(),
                  headers=[("tenant_id", tenant.encode())], on_delivery=on_delivery)
producer.flush(10)
print(result.get("partition", -1))
PYEOF
}

find_agent_for_owner() {
    # $1 = target owner IP, $2 = marker (for throwaway candidate agent
    # ids). Tries candidate agents one real alert at a time until one
    # lands on a partition the target currently owns. Prints the winning
    # agent id and partition as "AGENT=... PARTITION=..." on success;
    # prints nothing and returns 1 if exhausted - never guesses.
    local target_ip="$1" marker="$2"
    local attempt=1 max_attempts=40
    while [ "$attempt" -le "$max_attempts" ]; do
        local candidate="chaos-${marker}-try${attempt}"
        local partition owner
        partition="$(produce_probe "$candidate")"
        owner="$(owner_of_partition "$partition" "$(describe_group)")"
        echo "  attempt $attempt: agent=$candidate -> partition=$partition owned by $owner" >&2
        if [ "$owner" = "$target_ip" ]; then
            echo "AGENT=$candidate"
            echo "PARTITION=$partition"
            return 0
        fi
        attempt=$((attempt + 1))
    done
    return 1
}

run_cycle() {
    local run_label="$1" target_ip="$2" victim_name="$3" victim_ip="$4" survivor_name="$5" survivor_ip="$6"

    echo
    echo "=== Run $run_label: target owner = $victim_name ($target_ip) ==="
    echo "--- initial correlator group split ---"
    local initial_describe c1_count c2_count total
    initial_describe="$(describe_group)"
    echo "$initial_describe"
    c1_count="$(echo "$initial_describe" | grep -c "$C1_IP" || true)"
    c2_count="$(echo "$initial_describe" | grep -c "$C2_IP" || true)"
    total=$((c1_count + c2_count))
    check "[$run_label] correlate-1 owns 12 partitions before this run" "[ \"$c1_count\" = 12 ]"
    check "[$run_label] correlate-2 owns 12 partitions before this run" "[ \"$c2_count\" = 12 ]"
    check "[$run_label] total owned = 24 before this run" "[ \"$total\" = 24 ]"

    echo "--- searching for an agent whose partition is owned by $victim_name ---"
    local marker="${run_label}$(date +%s)"
    local find_output agent partition
    if ! find_output="$(find_agent_for_owner "$target_ip" "$marker")"; then
        echo "FAIL: [$run_label] could not find any agent owned by $victim_name ($target_ip) within attempt budget"
        fail=1
        return
    fi
    agent="$(echo "$find_output" | grep '^AGENT=' | cut -d= -f2)"
    partition="$(echo "$find_output" | grep '^PARTITION=' | cut -d= -f2)"
    check "[$run_label] owner lookup found a real agent/partition/container" "[ -n \"$agent\" ] && [ -n \"$partition\" ]"
    echo ">>> PROOF: agent=$agent  partition=$partition  owner_container=$victim_name  owner_ip=$target_ip  (before the kill)"

    echo "--- baseline survivor ($survivor_name) metrics ---"
    local metrics_before alerts_dup_before
    metrics_before="$(scrape_metrics "$survivor_name")"
    alerts_dup_before="$(echo "$metrics_before" | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('alerts_duplicate', 0))" 2>/dev/null || echo "")"

    echo "--- steady stream of $N_STREAM alerts (kill issued mid-stream, no pause) ---"
    local stream_output
    stream_output="$("$PY" - "$KAFKA_BOOTSTRAP" "$TENANT_KEY" "$agent" "$victim_name" "$N_STREAM" "$KILL_AFTER" "$RATE_HZ" \
        127.0.0.1 5432 "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$POSTGRES_DB" <<'PYEOF'
import json, sys, time, subprocess
import psycopg2
from confluent_kafka import Producer

(bootstrap, tenant, agent, victim, n_stream, kill_after, rate_hz,
 pg_host, pg_port, pg_user, pg_password, pg_db) = sys.argv[1:13]
n_stream, kill_after, rate_hz = int(n_stream), int(kill_after), float(rate_hz)

def alert(alert_id):
    return json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
        "id": alert_id,
        "rule": {"id": "5710", "level": 5, "description": "sshd authentication failure", "groups": ["sshd", "authentication_failed"]},
        "agent": {"id": agent, "name": agent, "ip": "172.28.0.99"},
        "manager": {"name": "wazuh-worker1"},
        "cluster": {"node": "worker1"},
        "data": {"srcip": "203.0.113.77"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": "Failed password for invalid user root from 203.0.113.77 port 51000 ssh2",
    })

conn = psycopg2.connect(host=pg_host, port=pg_port, user=pg_user, password=pg_password, dbname=pg_db)
conn.autocommit = True
cur = conn.cursor()

def get_count():
    cur.execute("SELECT alert_count FROM incidents WHERE tenant_key=%s AND agent_id=%s", (tenant, agent))
    row = cur.fetchone()
    return row[0] if row else None

producer = Producer({"bootstrap.servers": bootstrap})
key = f"{tenant}:{agent}".encode()
interval = 1.0 / rate_hz

kill_time = None
count_before_kill = None
t_resume = None

for i in range(1, n_stream + 1):
    producer.produce("shadowtracer.events.raw", key=key, value=alert(f"{agent}.s{i}").encode(),
                      headers=[("tenant_id", tenant.encode())])
    producer.poll(0)
    if i == kill_after:
        # BLOCKING, not Popen: `docker kill` only returns once dockerd
        # confirms SIGKILL was delivered - the one place this stream
        # pauses at all is for however long that syscall round-trip takes
        # (tens-to-low-hundreds of ms), not an artificial batch gap. This
        # matters for correctness, not just style: a non-blocking kill
        # issued here and immediately followed by a same-iteration
        # get_count() check (the first version of this script did this)
        # races the still-alive victim finishing the message it had
        # already dequeued, before SIGKILL has actually landed - which
        # measures "the dying consumer's last gasp", not real failover.
        # Capturing count_before_kill only AFTER the kill is confirmed
        # delivered removes that race entirely: the victim is
        # unconditionally dead by the time this count is read, so any
        # later increase can only be the survivor's.
        subprocess.run(["docker", "kill", victim], capture_output=True)
        kill_time = time.time()
        count_before_kill = get_count() or 0
    if kill_time is not None and t_resume is None:
        c = get_count()
        if c is not None and c > count_before_kill:
            t_resume = time.time()
    time.sleep(interval)
producer.flush(10)

# Keep polling after the stream ends for the incident to fully catch up
# (rebalance + survivor processing the backlog) and for t_resume if the
# tight per-message loop above hadn't caught it yet.
deadline = time.time() + 150
final_count = get_count() or 0
while time.time() < deadline:
    final_count = get_count() or 0
    if t_resume is None and count_before_kill is not None and final_count > count_before_kill:
        t_resume = time.time()
    if final_count >= n_stream + 1:  # +1 for the probe alert that created the incident
        break
    time.sleep(0.3)

cur.execute("SELECT id FROM incidents WHERE tenant_key=%s AND agent_id=%s", (tenant, agent))
rows = cur.fetchall()
incident_rows = len(rows)
incident_id = rows[0][0] if rows else None

dup = -1
if incident_id is not None:
    cur.execute("""
        SELECT count(*) FROM (
            SELECT tenant_key, node, alert_id, count(*) c FROM incident_alerts
            WHERE tenant_key=%s AND incident_id=%s GROUP BY tenant_key, node, alert_id HAVING count(*) > 1
        ) d
    """, (tenant, incident_id))
    dup = cur.fetchone()[0]

print(f"COUNT_BEFORE_KILL={count_before_kill}")
print(f"KILL_TIME={kill_time}")
print(f"T_RESUME={t_resume}")
print(f"FINAL_ALERT_COUNT={final_count}")
print(f"INCIDENT_ROWS={incident_rows}")
print(f"INCIDENT_ID={incident_id}")
print(f"DUP_MEMBERSHIPS={dup}")
PYEOF
)"
    echo "$stream_output"

    local final_alert_count incident_rows dup_memberships kill_time t_resume expected_total
    final_alert_count="$(echo "$stream_output" | grep '^FINAL_ALERT_COUNT=' | cut -d= -f2)"
    incident_rows="$(echo "$stream_output" | grep '^INCIDENT_ROWS=' | cut -d= -f2)"
    dup_memberships="$(echo "$stream_output" | grep '^DUP_MEMBERSHIPS=' | cut -d= -f2)"
    kill_time="$(echo "$stream_output" | grep '^KILL_TIME=' | cut -d= -f2)"
    t_resume="$(echo "$stream_output" | grep '^T_RESUME=' | cut -d= -f2)"
    expected_total=$((N_STREAM + 1))

    check "[$run_label] exactly ONE incident for this agent" "[ \"$incident_rows\" = 1 ]"
    check "[$run_label] alert_count equals every alert produced ($expected_total)" "[ \"$final_alert_count\" = \"$expected_total\" ]"
    check "[$run_label] incident_alerts has no duplicate (tenant_key, node, alert_id)" "[ \"$dup_memberships\" = 0 ]"

    if [ "$t_resume" != "None" ] && [ -n "$t_resume" ] && [ "$kill_time" != "None" ] && [ -n "$kill_time" ]; then
        local failover
        failover="$("$PY" -c "print(f'{$t_resume - $kill_time:.2f}')")"
        echo ">>> FAILOVER TIME [$run_label]: ${failover}s (T_kill=$kill_time, T_resume=$t_resume)"
        failover_times+=("$failover")
    else
        echo "FAIL: [$run_label] could not measure failover (T_resume never observed within the poll window)"
        fail=1
    fi

    echo "--- survivor ($survivor_name) metrics after redelivery ---"
    local metrics_after alerts_dup_after
    metrics_after="$(scrape_metrics "$survivor_name")"
    alerts_dup_after="$(echo "$metrics_after" | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('alerts_duplicate', 0))" 2>/dev/null || echo "")"
    if [ -n "$alerts_dup_before" ] && [ -n "$alerts_dup_after" ]; then
        echo "redelivered-and-deduplicated messages (survivor's alerts_duplicate delta): $((alerts_dup_after - alerts_dup_before))"
    else
        echo "redelivered-and-deduplicated count: NOT AVAILABLE (metrics scrape failed for $survivor_name - not invented)"
    fi

    echo "--- restart $victim_name, confirm it rejoins the group ---"
    docker start "$victim_name" >/dev/null
    local deadline healthy
    deadline=$(( $(date +%s) + 60 ))
    healthy=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        healthy="$(docker inspect -f '{{.State.Health.Status}}' "$victim_name" 2>/dev/null || true)"
        [ "$healthy" = "healthy" ] && break
        sleep 2
    done
    check "[$run_label] $victim_name is healthy again after restart" "[ \"$healthy\" = healthy ]"

    deadline=$(( $(date +%s) + 60 ))
    local rejoined_count=0 final_describe
    while [ "$(date +%s)" -lt "$deadline" ]; do
        final_describe="$(describe_group)"
        rejoined_count="$(echo "$final_describe" | grep -c "$victim_ip" || true)"
        [ "$rejoined_count" -gt 0 ] && break
        sleep 3
    done
    check "[$run_label] $victim_name rejoined the group (owns >0 partitions again)" "[ \"$rejoined_count\" -gt 0 ]"

    # Let the group fully re-stabilize to a clean 12/12 before the next
    # run starts - otherwise its own "12/12 before this run" check can
    # catch a mid-rebalance snapshot and flake.
    deadline=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        final_describe="$(describe_group)"
        c1_count="$(echo "$final_describe" | grep -c "$C1_IP" || true)"
        c2_count="$(echo "$final_describe" | grep -c "$C2_IP" || true)"
        [ "$c1_count" = 12 ] && [ "$c2_count" = 12 ] && break
        sleep 3
    done
    echo "post-rejoin split: correlate-1=$c1_count correlate-2=$c2_count"

    echo "--- cleanup: removing this run's chaos-test incidents ---"
    docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
        DELETE FROM incident_alerts WHERE tenant_key = '$TENANT_KEY'
            AND incident_id IN (SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id LIKE 'chaos-${marker}-%');
        DELETE FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id LIKE 'chaos-${marker}-%';
    " >/dev/null
}

run_cycle "1" "$C1_IP" "$C1_NAME" "$C1_IP" "$C2_NAME" "$C2_IP"
run_cycle "2" "$C2_IP" "$C2_NAME" "$C2_IP" "$C1_NAME" "$C1_IP"
run_cycle "3" "$C1_IP" "$C1_NAME" "$C1_IP" "$C2_NAME" "$C2_IP"

echo
echo "=== Failover times (all 3 runs) ==="
for i in "${!failover_times[@]}"; do
    echo "run $((i + 1)): ${failover_times[$i]}s"
done
echo
echo "librdkafka's documented default session.timeout.ms is 45000ms (45s) -"
echo "the broker only reassigns a dead member's partitions once its session"
echo "expires, since docker kill (SIGKILL) gives the consumer no chance to"
echo "send a graceful LeaveGroup first. If the numbers above cluster near"
echo "45s, that default is what's driving it, not anything this project"
echo "configured. Not tuned here per instruction - report only."

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "VERIFY-CORRELATOR-CHAOS: PASS"
else
    echo "VERIFY-CORRELATOR-CHAOS: FAIL"
fi
exit "$fail"
