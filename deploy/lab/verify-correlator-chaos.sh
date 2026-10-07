#!/usr/bin/env bash
# Phase 5A hardening: replaces the thread-abandon as the "kill a
# correlation worker mid-attack" evidence with a REAL container kill
# against the real, running lab - `docker kill` on an actual
# correlate-1/correlate-2 container, not a Python thread dropped in a test
# process. Also captures the real partition split for the CORRELATOR
# consumer group specifically (the original VERIFY doc showed this for
# the WRITER group instead, which is a different consumer group entirely
# - shadowtracer-writer vs shadowtracer-correlate, see docker-compose.yml's
# x-writer-env/x-correlate-env KAFKA_GROUP_ID).
#
# Container names and the consumer group name are read from
# docker-compose.yml, not guessed:
#   - group id:        x-correlate-env's KAFKA_GROUP_ID = shadowtracer-correlate
#   - containers:      correlate-1, correlate-2 services -> compose's
#                       default naming, shadowtracer-lab-correlate-{1,2}-1
#   - static IPs:       172.28.0.42 (correlate-1), 172.28.0.43 (correlate-2)
#                       (correlate-1/correlate-2 services' ipv4_address)
# The IP->container map below is these 2 fixed addresses, nothing else.
#
# Run from deploy/lab/: ./verify-correlator-chaos.sh
set -uo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

GROUP=shadowtracer-correlate
TOPIC=shadowtracer.events.raw
KAFKA_BOOTSTRAP=127.0.0.1:9094
PY="../../shadowtracer/correlate/.venv/bin/python3"

C1_IP=172.28.0.42   # correlate-1
C2_IP=172.28.0.43   # correlate-2
C1_NAME=shadowtracer-lab-correlate-1-1
C2_NAME=shadowtracer-lab-correlate-2-1

MARKER="chaos$(date +%s)"
AGENT="chaos-agent-${MARKER}"
N_ALERTS=10
KILL_AFTER=3

fail=0
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
    # $1 = partition number; prints the owning consumer's HOST (bare IP,
    # no leading '/' - kafka-consumer-groups.sh's HOST column prints it
    # as /x.x.x.x). Column layout: GROUP TOPIC PARTITION CURRENT-OFFSET
    # LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID.
    echo "$group_describe_output" | awk -v p="$1" '$3 == p { print $8 }' | head -1 | tr -d '/'
}

produce_probe() {
    # Produces one alert for $AGENT and prints the partition Kafka assigned it to.
    "$PY" - "$KAFKA_BOOTSTRAP" "$TENANT_KEY" "$AGENT" <<'PYEOF'
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

produce_burst() {
    # $1 = starting index, $2 = count
    "$PY" - "$KAFKA_BOOTSTRAP" "$TENANT_KEY" "$AGENT" "$1" "$2" <<'PYEOF'
import json, sys, time
from confluent_kafka import Producer

bootstrap, tenant, agent, start, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])

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
for i in range(start, start + count):
    producer.produce("shadowtracer.events.raw", key=key, value=alert(f"{agent}.{i}").encode(),
                      headers=[("tenant_id", tenant.encode())])
producer.flush(10)
PYEOF
}

psql_query() {
    docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$1"
}

echo "=== 1. Correlator consumer group partition split (real, 2 correlators) ==="
group_describe_output="$(describe_group)"
echo "$group_describe_output"
c1_count="$(echo "$group_describe_output" | grep -c "$C1_IP" || true)"
c2_count="$(echo "$group_describe_output" | grep -c "$C2_IP" || true)"
total=$((c1_count + c2_count))
check "correlate-1 ($C1_IP) owns 12 partitions" "[ \"$c1_count\" = 12 ]"
check "correlate-2 ($C2_IP) owns 12 partitions" "[ \"$c2_count\" = 12 ]"
check "total owned = 24" "[ \"$total\" = 24 ]"

echo
echo "=== 2. Chaos: kill the correlator owning a real, growing incident's partition ==="
probe_partition="$(produce_probe)"
echo "agent $AGENT's events land on partition $probe_partition"
owner_ip="$(owner_of_partition "$probe_partition")"
echo "partition $probe_partition is currently owned by $owner_ip"

if [ "$owner_ip" = "$C1_IP" ]; then
    victim_name="$C1_NAME"; victim_ip="$C1_IP"; survivor_ip="$C2_IP"
elif [ "$owner_ip" = "$C2_IP" ]; then
    victim_name="$C2_NAME"; victim_ip="$C2_IP"; survivor_ip="$C1_IP"
else
    echo "FAIL: could not determine partition $probe_partition's owner from group describe output"
    exit 1
fi
echo "will kill $victim_name (owns partition $probe_partition)"

# Wait for the probe alert to land as a real incident before producing more.
deadline=$(( $(date +%s) + 20 ))
alert_count=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    alert_count="$(psql_query "SELECT alert_count FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT'")"
    [ -n "$alert_count" ] && [ "$alert_count" -ge 1 ] && break
    sleep 1
done
check "incident exists and is growing before the kill (alert_count >= 1)" "[ -n \"$alert_count\" ] && [ \"$alert_count\" -ge 1 ]"

# Produce a few more while the incident is open, confirm it keeps growing,
# THEN kill mid-attack - not after the attack has already finished.
produce_burst 1 "$KILL_AFTER"
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    alert_count="$(psql_query "SELECT alert_count FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT'")"
    [ "$alert_count" = "$((KILL_AFTER + 1))" ] && break
    sleep 1
done
check "incident grew to $((KILL_AFTER + 1)) alerts before the kill" "[ \"$alert_count\" = \"$((KILL_AFTER + 1))\" ]"

echo "killing $victim_name now (docker kill, not a graceful stop)..."
docker kill "$victim_name" >/dev/null

# Produce the rest of the "attack" WHILE the group is down to one member -
# these alerts sit unconsumed on the dead partition until the rebalance
# hands it to the survivor.
remaining=$((N_ALERTS - KILL_AFTER - 1))
produce_burst "$((KILL_AFTER + 2))" "$remaining"

echo "=== 3. Rebalance: survivor must pick up all 24 partitions ==="
deadline=$(( $(date +%s) + 120 ))
survivor_total=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    rebalance_output="$(describe_group)"
    survivor_total="$(echo "$rebalance_output" | grep -c "$survivor_ip" || true)"
    [ "$survivor_total" = 24 ] && break
    sleep 3
done
echo "$rebalance_output"
check "survivor owns all 24 partitions after the kill" "[ \"$survivor_total\" = 24 ]"

echo
echo "=== 4. The incident survives and keeps growing across the outage ==="
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    alert_count="$(psql_query "SELECT alert_count FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT'")"
    [ "$alert_count" = "$N_ALERTS" ] && break
    sleep 2
done
incident_rows="$(psql_query "SELECT count(*) FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT'")"
incident_id="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT'")"
dup_memberships="$(psql_query "
    SELECT count(*) FROM (
        SELECT tenant_key, node, alert_id, count(*) AS c
        FROM incident_alerts WHERE tenant_key = '$TENANT_KEY'
          AND incident_id = (SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT')
        GROUP BY tenant_key, node, alert_id HAVING count(*) > 1
    ) d
")"

echo "--- final incident row ---"
docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    SELECT id, agent_id, correlation_basis, alert_count, state FROM incidents
    WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT';
"

echo "incident id: $incident_id"
check "exactly ONE incident for this agent (no split across the kill)" "[ \"$incident_rows\" = 1 ]"
check "alert_count equals every alert produced ($N_ALERTS)" "[ \"$alert_count\" = \"$N_ALERTS\" ]"
check "incident_alerts has no duplicate (tenant_key, node, alert_id)" "[ \"$dup_memberships\" = 0 ]"

echo
echo "=== 5. Restart the killed container, confirm it rejoins the group ==="
docker start "$victim_name" >/dev/null
deadline=$(( $(date +%s) + 60 ))
healthy=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    healthy="$(docker inspect -f '{{.State.Health.Status}}' "$victim_name" 2>/dev/null || true)"
    [ "$healthy" = "healthy" ] && break
    sleep 2
done
check "$victim_name is healthy again after restart" "[ \"$healthy\" = healthy ]"

deadline=$(( $(date +%s) + 60 ))
rejoined_count=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    final_output="$(describe_group)"
    rejoined_count="$(echo "$final_output" | grep -c "$victim_ip" || true)"
    [ "$rejoined_count" -gt 0 ] && break
    sleep 3
done
echo "$final_output"
check "$victim_name rejoined the group (owns >0 partitions again)" "[ \"$rejoined_count\" -gt 0 ]"
final_total=$(( rejoined_count + $(echo "$final_output" | grep -c "$survivor_ip" || true) ))
check "total still 24 after rejoin" "[ \"$final_total\" = 24 ]"

echo
echo "--- cleanup: removing this run's chaos-test incident/alerts ---"
docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    DELETE FROM incident_alerts WHERE tenant_key = '$TENANT_KEY'
        AND incident_id IN (SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT');
    DELETE FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$AGENT';
" >/dev/null

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "VERIFY-CORRELATOR-CHAOS: PASS"
else
    echo "VERIFY-CORRELATOR-CHAOS: FAIL"
fi
exit "$fail"
