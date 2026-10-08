#!/usr/bin/env bash
# Phase 5B VERIFY: campaign linking, rare-pattern alerting, sequence
# detection - real lab only, nothing mocked, same standard as Phase 5A's
# verify-correlator-chaos.sh (which this reuses the kill-mid-sequence
# technique from).
#
# Run from deploy/lab/: ./verify-phase5b.sh
set -uo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

PY_CORRELATE="../../shadowtracer/correlate/.venv/bin/python3"
PY_BACKEND="../../shadowtracer/console/backend/.venv/bin/python3"
KAFKA_BOOTSTRAP=127.0.0.1:9094
GROUP=shadowtracer-correlate
INTERNAL_RANGES="172.28.0.0/24"

C1_IP=172.28.0.42
C2_IP=172.28.0.43
C1_NAME=shadowtracer-lab-correlate-1-1
C2_NAME=shadowtracer-lab-correlate-2-1

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

psql_query() {
    docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$1"
}
psql_exec() {
    docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"
}
ch_query() {
    docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client --query "$1"
}
describe_group() {
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server localhost:9092 --describe --group "$GROUP"
}
owner_of_partition() {
    echo "$2" | awk -v p="$1" '$3 == p { print $8 }' | head -1 | tr -d '/'
}

# Produces one real sshd alert through the real events.raw topic.
# args: tenant agent src_ip rule_groups_csv alert_id_suffix
produce_alert() {
    "$PY_CORRELATE" - "$KAFKA_BOOTSTRAP" "$1" "$2" "$3" "$4" "$5" <<'PYEOF'
import json, sys, time
from confluent_kafka import Producer

bootstrap, tenant, agent, src_ip, groups_csv, suffix = sys.argv[1:7]
groups = groups_csv.split(",")

alert = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
    "id": f"{agent}.{suffix}",
    "rule": {"id": "5710", "level": 5, "description": "test", "groups": groups},
    "agent": {"id": agent, "name": agent, "ip": "172.28.0.99"},
    "manager": {"name": "wazuh-worker1"},
    "cluster": {"node": "worker1"},
    "data": {"srcip": src_ip},
    "decoder": {"name": "sshd"},
    "location": "/var/log/auth.log",
    "full_log": "test",
}
producer = Producer({"bootstrap.servers": bootstrap})
producer.produce("shadowtracer.events.raw", key=f"{tenant}:{agent}".encode(),
                  value=json.dumps(alert).encode(), headers=[("tenant_id", tenant.encode())])
producer.flush(10)
PYEOF
}

# Closes whatever's quiet right now, with a short session gap - the same
# technique Phase 5A's own VERIFY used (never backdating timestamps,
# which corrupts the fingerprint's duration bucket - found the hard way
# then). Runs against the REAL lab database/ClickHouse directly, once,
# not a running loop - minimizes how long any other tenant's genuinely
# in-progress incident could be swept early.
close_sweep() {
    "$PY_CORRELATE" - "$DATABASE_URL_APP" "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" "$INTERNAL_RANGES" <<'PYEOF'
import sys
sys.path.insert(0, "../../shadowtracer/correlate")
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import clickhouse_connect
from shadowtracer_correlate.closer import close_eligible_incidents

database_url, ch_user, ch_password, internal_ranges = sys.argv[1:5]
engine = create_engine(database_url)
db = sessionmaker(bind=engine, expire_on_commit=False)()
ch = clickhouse_connect.get_client(host="127.0.0.1", port=8123, username=ch_user, password=ch_password)
closed = close_eligible_incidents(db, ch, "shadowtracer", session_gap_seconds=5, internal_ranges=internal_ranges.split(","))
print("closed:", closed)
PYEOF
}

DATABASE_URL_APP="postgresql+psycopg2://shadowtracer_app:${APP_DB_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"

echo "=== Phase 5B VERIFY ==="
echo
echo "--- 1. Campaign linking: brute force repeated twice from one IP within 24h -> ONE campaign, 2 incidents ---"
marker="camp$(date +%s)"
agent="camp-agent-${marker}"
ip_a="203.0.113.$((RANDOM % 200 + 10))"
ip_b="203.0.113.$((RANDOM % 55 + 210))"

produce_alert "$TENANT_KEY" "$agent" "$ip_a" "sshd,authentication_failed" "1"
sleep 8
close_sweep
id1="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$agent' ORDER BY id LIMIT 1")"
check "incident 1 closed" "[ -n \"$id1\" ]"

produce_alert "$TENANT_KEY" "$agent" "$ip_a" "sshd,authentication_failed" "2"
sleep 8
close_sweep
id2="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$agent' AND id != $id1 ORDER BY id LIMIT 1")"
check "incident 2 (same IP) closed" "[ -n \"$id2\" ]"

echo "--- real SQL: campaigns for incidents 1 and 2 ---"
psql_exec "
SELECT ci.incident_id, c.id AS campaign_id, c.actor_value, c.incident_count
FROM campaign_incidents ci JOIN campaigns c ON c.id = ci.campaign_id
WHERE ci.incident_id IN ($id1, $id2) ORDER BY ci.incident_id;
"
campaign1="$(psql_query "SELECT campaign_id FROM campaign_incidents WHERE incident_id = $id1")"
campaign2="$(psql_query "SELECT campaign_id FROM campaign_incidents WHERE incident_id = $id2")"
check "same actor within 24h -> SAME campaign" "[ \"$campaign1\" = \"$campaign2\" ] && [ -n \"$campaign1\" ]"
incident_count="$(psql_query "SELECT incident_count FROM campaigns WHERE id = $campaign1")"
check "campaign incident_count is 2" "[ \"$incident_count\" = 2 ]"

produce_alert "$TENANT_KEY" "$agent" "$ip_b" "sshd,authentication_failed" "3"
sleep 8
close_sweep
id3="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$TENANT_KEY' AND agent_id = '$agent' AND id NOT IN ($id1, $id2) ORDER BY id LIMIT 1")"
check "incident 3 (different IP) closed" "[ -n \"$id3\" ]"

fp1="$(psql_query "SELECT fingerprint_key FROM incidents WHERE id = $id1")"
fp3="$(psql_query "SELECT fingerprint_key FROM incidents WHERE id = $id3")"
campaign3="$(psql_query "SELECT campaign_id FROM campaign_incidents WHERE incident_id = $id3")"
echo "--- real SQL: incident 3's fingerprint vs incident 1's, and its campaign ---"
psql_exec "SELECT id, fingerprint_key FROM incidents WHERE id IN ($id1, $id3);"
check "same fingerprint (different IP, same internal/external classification)" "[ \"$fp1\" = \"$fp3\" ]"
check "different actor -> SEPARATE campaign" "[ \"$campaign3\" != \"$campaign1\" ]"

echo
echo "--- 2. Rare-pattern alerting: warm-up guard ---"
echo "real lab tenant's current warm-up status (expected incomplete - this IS the 'fresh tenant' case, real data, not fabricated):"
login_resp="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/auth/login \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"$SMOKE_TEST_ADMIN_EMAIL\",\"password\":\"$SMOKE_TEST_ADMIN_PASSWORD\"}")"
lab_token="$(echo "$login_resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')"
lab_warmup="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/api/rare-pattern-warmup-status -H "Authorization: Bearer $lab_token")"
echo "$lab_warmup"
lab_complete="$(echo "$lab_warmup" | python3 -c 'import sys,json; print(json.load(sys.stdin)["complete"])')"
check "real lab tenant has not finished warm-up" "[ \"$lab_complete\" = False ]"
check "no rare-pattern flags during warm-up (real lab tenant)" \
    "[ \"$(psql_query "SELECT count(*) FROM incidents WHERE tenant_key = '$TENANT_KEY' AND rare_pattern_flag = true")\" = 0 ]"

echo
echo "--- setting up a fresh tenant with a low warm-up override (per-tenant config, as designed) ---"
rare_marker="rare$(date +%s)"
rare_tenant_name="verify-rare-${rare_marker}"
setup_output="$("$PY_BACKEND" - "$rare_tenant_name" "rare-${rare_marker}@example.com" <<'PYEOF'
import secrets, sys
sys.path.insert(0, "../../shadowtracer/console/backend")
from app import security
from app.config import load_settings
from app.db import make_session_factory
from app.models import tenants, users

tenant_name, email = sys.argv[1], sys.argv[2]
settings = load_settings()
Session = make_session_factory(settings)
db = Session()

tenant_key = secrets.token_hex(16)
tenant_id = db.execute(tenants.insert().values(name=tenant_name, tenant_key=tenant_key).returning(tenants.c.id)).scalar_one()
db.execute(users.insert().values(
    tenant_id=tenant_id, email=email, password_hash=security.hash_password("VerifyRarePass123!"), role="admin",
))
db.commit()
print(f"TENANT_KEY={tenant_key}")
PYEOF
)"
rare_tenant_key="$(echo "$setup_output" | grep '^TENANT_KEY=' | cut -d= -f2)"
check "fresh tenant created" "[ -n \"$rare_tenant_key\" ]"

psql_exec "INSERT INTO tenant_alert_settings (tenant_key, rare_alert_warmup_days, rare_alert_warmup_min_incidents) VALUES ('$rare_tenant_key', 0, 1);" >/dev/null

rare_email="rare-${rare_marker}@example.com"
rare_login="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/auth/login \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"$rare_email\",\"password\":\"VerifyRarePass123!\"}")"
rare_token="$(echo "$rare_login" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')"

rare_agent="rare-agent-${rare_marker}"
produce_alert "$rare_tenant_key" "$rare_agent" "203.0.113.90" "sshd,authentication_failed,recon" "1"
sleep 8
close_sweep
rare_incident_id="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$rare_tenant_key' AND agent_id = '$rare_agent'")"
check "fresh tenant's first incident closed" "[ -n \"$rare_incident_id\" ]"

rare_warmup="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/api/rare-pattern-warmup-status -H "Authorization: Bearer $rare_token")"
echo "fresh tenant's warm-up status (overridden to 0 days / 1 incident): $rare_warmup"
rare_complete="$(echo "$rare_warmup" | python3 -c 'import sys,json; print(json.load(sys.stdin)["complete"])')"
check "overridden tenant is past warm-up" "[ \"$rare_complete\" = True ]"

echo "--- real API: GET /api/incidents for the fresh tenant (never-seen fingerprint) ---"
rare_incidents="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/api/incidents -H "Authorization: Bearer $rare_token")"
echo "$rare_incidents" | python3 -m json.tool
rare_flag="$(echo "$rare_incidents" | python3 -c "
import sys, json
items = json.load(sys.stdin)['incidents']
row = next(i for i in items if i['id'] == $rare_incident_id)
print(row['rare_pattern_flag'], row['rare_pattern_occurrence_count'])
")"
check "never-seen fingerprint gets a rare flag with occurrence count 0" "[ \"$rare_flag\" = 'True 0' ]"

echo
echo "--- 3. Sequence detection: fires once, replay-safe, survives a real correlator crash ---"
seq_marker="seq$(date +%s)"
seq_agent="seqv-agent-${seq_marker}"
seq_ip="203.0.113.$((RANDOM % 50 + 150))"

probe_partition="$("$PY_CORRELATE" - "$KAFKA_BOOTSTRAP" "$TENANT_KEY" "${seq_agent}-probe" <<'PYEOF'
import json, sys, time
from confluent_kafka import Producer
bootstrap, tenant, agent = sys.argv[1:4]
producer = Producer({"bootstrap.servers": bootstrap})
result = {}
def on_delivery(err, msg):
    if err is None:
        result["partition"] = msg.partition()
alert = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()), "id": f"{agent}.probe",
         "rule": {"id": "5710", "level": 5, "description": "probe", "groups": ["sshd"]},
         "agent": {"id": agent, "name": agent, "ip": "172.28.0.99"}, "manager": {"name": "wazuh-worker1"},
         "cluster": {"node": "worker1"}, "data": {"srcip": "1.1.1.1"}, "decoder": {"name": "sshd"},
         "location": "x", "full_log": "x"}
producer.produce("shadowtracer.events.raw", key=f"{tenant}:{agent}".encode(), value=json.dumps(alert).encode(),
                  headers=[("tenant_id", tenant.encode())], on_delivery=on_delivery)
producer.flush(10)
print(result.get("partition", -1))
PYEOF
)"
owner_ip="$(owner_of_partition "$probe_partition" "$(describe_group)")"
if [ "$owner_ip" = "$C1_IP" ]; then victim_name="$C1_NAME"; victim_ip="$C1_IP"; else victim_name="$C2_NAME"; victim_ip="$C2_IP"; fi
echo "sequence test agent's partition ($probe_partition) is owned by $victim_name"

produce_alert "$TENANT_KEY" "$seq_agent" "$seq_ip" "sshd,authentication_failed" "step0"
sleep 5
echo "killing $victim_name (docker kill) between step 0 and step 1..."
docker kill "$victim_name" >/dev/null

produce_alert "$TENANT_KEY" "$seq_agent" "$seq_ip" "sshd,authentication_success" "step1"

echo "waiting for rebalance + survivor to process the completing alert (real session.timeout.ms wait, ~50s)..."
deadline=$(( $(date +%s) + 120 ))
firing_count=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    firing_count="$(ch_query "SELECT uniqExact(completing_alert_id) FROM shadowtracer.sequence_firings WHERE agent_id = '$seq_agent'")"
    [ "$firing_count" = 1 ] && break
    sleep 3
done
echo "--- real ClickHouse: the firing, with step_matches ---"
ch_query "SELECT sequence_id, agent_id, step_matches FROM shadowtracer.sequence_firings WHERE agent_id = '$seq_agent' FORMAT Vertical"
check "sequence completed correctly on the survivor after the kill" "[ \"$firing_count\" = 1 ]"

docker start "$victim_name" >/dev/null
deadline=$(( $(date +%s) + 60 ))
healthy=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    healthy="$(docker inspect -f '{{.State.Health.Status}}' "$victim_name" 2>/dev/null || true)"
    [ "$healthy" = "healthy" ] && break
    sleep 2
done
check "$victim_name is healthy again after restart" "[ \"$healthy\" = healthy ]"

# Restarting the victim triggers a SECOND rebalance (it rejoining the
# group) - found the hard way: without waiting for this one too, the
# next section's freshly-produced alerts could land during that brief
# instability and take longer than expected to process, which looked
# like a false "doesn't fire" failure the first time this script ran.
echo "waiting for $victim_name to rejoin the consumer group (a second rebalance, not just container health)..."
deadline=$(( $(date +%s) + 60 ))
rejoined_count=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    rejoined_count="$(describe_group | grep -c "$victim_ip" || true)"
    [ "$rejoined_count" -gt 0 ] && break
    sleep 3
done
check "$victim_name rejoined the consumer group" "[ \"$rejoined_count\" -gt 0 ]"

echo
echo "--- replay safety: a fresh dedicated consumer group reading the whole topic from earliest must not double-fire ---"
replay_marker="replay$(date +%s)"
replay_agent="replayv-agent-${replay_marker}"
replay_ip="203.0.113.$((RANDOM % 50 + 1))"
produce_alert "$TENANT_KEY" "$replay_agent" "$replay_ip" "sshd,authentication_failed" "step0"
sleep 2
produce_alert "$TENANT_KEY" "$replay_agent" "$replay_ip" "sshd,authentication_success" "step1"

deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    first_fire="$(ch_query "SELECT uniqExact(completing_alert_id) FROM shadowtracer.sequence_firings WHERE agent_id = '$replay_agent'")"
    [ "$first_fire" = 1 ] && break
    sleep 2
done
check "fresh sequence fires once on first processing" "[ \"$first_fire\" = 1 ]"

echo "starting a temporary, isolated consumer group to replay the ENTIRE topic from earliest (never the live shadowtracer-correlate group - this doesn't touch its offsets at all)..."
"$PY_CORRELATE" - "$DATABASE_URL_APP" "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" <<'PYEOF'
import sys, threading, time, traceback
sys.path.insert(0, "../../shadowtracer/correlate")
from shadowtracer_correlate.consumer import run
from shadowtracer_correlate.metrics import Metrics
import clickhouse_connect

database_url, ch_user, ch_password = sys.argv[1:4]
ch = clickhouse_connect.get_client(host="127.0.0.1", port=8123, username=ch_user, password=ch_password, database="shadowtracer")
stop_flag = threading.Event()
started_flag = threading.Event()

def _run():
    try:
        run(
            bootstrap_servers="127.0.0.1:9094", topic="shadowtracer.events.raw",
            group_id=f"verify-replay-{int(time.time())}", database_url=database_url,
            metrics=Metrics(), stop_flag=stop_flag, started_flag=started_flag,
            ch_client=ch, clickhouse_database="shadowtracer",
            sequences_dir="../../shadowtracer/correlate/sequences",
        )
    except Exception:
        traceback.print_exc()
        started_flag.set()  # unblock the wait below so the failure is visible, not silently swallowed

t = threading.Thread(target=_run, daemon=True)
t.start()
if not started_flag.wait(timeout=10):
    print("REPLAY CONSUMER NEVER STARTED", file=sys.stderr)
time.sleep(60)  # let it drain the whole real topic's history once
stop_flag.set()
t.join(timeout=10)
print("replay consumer drained")
PYEOF

replay_fire_count="$(ch_query "SELECT uniqExact(completing_alert_id) FROM shadowtracer.sequence_firings WHERE agent_id = '$replay_agent'")"
check "replaying the whole topic from a fresh group does not fire it twice" "[ \"$replay_fire_count\" = 1 ]"

echo
echo "--- cleanup: removing this run's VERIFY data ---"
# Every DELETE here that targets "this run's incidents" uses the SAME
# 4-pattern agent_id filter, not an independently-maintained subset of
# it - found the hard way (2026-10-08, this same run): campaign_incidents'
# filter had only 2 of the 4 patterns, missing a sequence-test incident's
# campaign link, which made the later incidents DELETE hit a real FK
# violation and roll back this whole batch (psql -c runs multi-statement
# as one transaction - same failure shape as the earlier
# refresh_tokens/users FK-order bug, a different FK this time). Orphaned
# `campaigns` rows (both the camp-agent test's shared one and the
# solo ones auto-created for every other closed incident) are deleted by
# what's LEFT in campaign_incidents after that, not by listing actor_value
# IPs - a list that silently drifts out of sync is exactly what broke here.
psql_exec "
DELETE FROM campaign_incidents WHERE incident_id IN (
  SELECT id FROM incidents WHERE agent_id LIKE 'camp-agent-%' OR agent_id LIKE 'rare-agent-%'
  OR agent_id LIKE 'seqv-agent-%' OR agent_id LIKE 'replayv-agent-%'
);
DELETE FROM incident_alerts WHERE incident_id IN (
  SELECT id FROM incidents WHERE agent_id LIKE 'camp-agent-%' OR agent_id LIKE 'rare-agent-%'
  OR agent_id LIKE 'seqv-agent-%' OR agent_id LIKE 'replayv-agent-%'
);
DELETE FROM incidents WHERE agent_id LIKE 'camp-agent-%' OR agent_id LIKE 'rare-agent-%'
  OR agent_id LIKE 'seqv-agent-%' OR agent_id LIKE 'replayv-agent-%';
DELETE FROM campaigns WHERE tenant_key IN ('$TENANT_KEY', '$rare_tenant_key')
  AND id NOT IN (SELECT DISTINCT campaign_id FROM campaign_incidents);
DELETE FROM sequence_progress WHERE agent_id LIKE 'seqv-agent-%' OR agent_id LIKE 'replayv-agent-%';
DELETE FROM tenant_alert_settings WHERE tenant_key = '$rare_tenant_key';
DELETE FROM refresh_tokens WHERE user_id IN (
  SELECT id FROM users WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_key = '$rare_tenant_key')
);
DELETE FROM users WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_key = '$rare_tenant_key');
DELETE FROM tenants WHERE tenant_key = '$rare_tenant_key';
" >/dev/null
cutoff="$(date -u -d '15 minutes ago' '+%Y-%m-%d %H:%M:%S')"
ch_query "ALTER TABLE shadowtracer.sequence_firings DELETE WHERE (agent_id LIKE 'seqv-agent-%' OR agent_id LIKE 'replayv-agent-%') AND fired_at >= toDateTime64('$cutoff', 3)"
ch_query "ALTER TABLE shadowtracer.events DELETE WHERE (agent_id LIKE 'camp-agent-%' OR agent_id LIKE 'rare-agent-%' OR agent_id LIKE 'seqv-agent-%' OR agent_id LIKE 'replayv-agent-%') AND time >= toDateTime64('$cutoff', 3)"

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "VERIFY-PHASE5B: PASS"
else
    echo "VERIFY-PHASE5B: FAIL"
fi
exit "$fail"
