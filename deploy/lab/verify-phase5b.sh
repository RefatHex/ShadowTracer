#!/usr/bin/env bash
# Phase 5B VERIFY: campaign linking, rare-pattern alerting, sequence
# detection - real lab only, nothing mocked, same standard as Phase 5A's
# verify-correlator-chaos.sh (which this reuses the kill-mid-sequence
# technique from).
#
# Run from deploy/lab/: ./verify-phase5b.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1
set -a; source .env; set +a
# Phase 5.6 Item 1: admin (super-user, bypasses ACLs) - every Python
# Kafka client in this script is an operator/test-harness tool, not a
# real pipeline component, same credential create-kafka-topics.sh/
# create-kafka-acls.sh already use for the same reason.
export KAFKA_SECURITY_PROTOCOL=SASL_SSL
export KAFKA_SASL_USERNAME=admin
export KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD"
KAFKA_SSL_CA_LOCATION="$(pwd)/kafka-certs/ca.crt"; export KAFKA_SSL_CA_LOCATION

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
    # Real incident (Phase 5.6 closeout) - see verify-correlator-chaos.sh's
    # own describe_group for the full story: `kafka-consumer-groups.sh
    # --describe` aborts the ENTIRE command (zero output, nonzero exit)
    # the moment it tries to resolve log-end-offsets for ANY partition
    # whose topic no longer exists - confirmed directly, triggered here
    # by the same stale ephemeral-test-topic reference. AdminClient.
    # describe_consumer_groups() only reports the group's CURRENT live
    # assignment, never historical committed-offset entries, so a
    # long-gone topic never appears. Same 9-column layout the CLI tool
    # printed (GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG
    # CONSUMER-ID HOST CLIENT-ID, HOST as /x.x.x.x) so owner_of_partition
    # keeps working unchanged.
    "$PY_CORRELATE" - "$GROUP" "$KAFKA_BOOTSTRAP" <<'PYEOF'
import sys
from confluent_kafka import Consumer, TopicPartition, ConsumerGroupTopicPartitions
from confluent_kafka.admin import AdminClient
sys.path.insert(0, "../../shadowtracer/ingest")
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env

group, bootstrap = sys.argv[1], sys.argv[2]
cfg = kafka_client_config_from_env()
admin = AdminClient({"bootstrap.servers": bootstrap, **cfg})

desc = admin.describe_consumer_groups([group])[group].result(timeout=10)
consumer = Consumer({
    "bootstrap.servers": bootstrap, "group.id": "verify-phase5b-describe",
    "enable.auto.commit": False, **cfg,
})
offs = admin.list_consumer_group_offsets([ConsumerGroupTopicPartitions(group)])[group].result(timeout=10)
committed = {(tp.topic, tp.partition): tp.offset for tp in offs.topic_partitions}

for m in desc.members:
    if not m.assignment:
        continue
    for tp in m.assignment.topic_partitions:
        try:
            low, high = consumer.get_watermark_offsets(TopicPartition(tp.topic, tp.partition), timeout=5, cached=False)
        except Exception:
            continue  # the exact crash this replaces the CLI tool to avoid - skip, don't abort
        cur = committed.get((tp.topic, tp.partition), low)
        host = m.host if m.host.startswith("/") else f"/{m.host}"
        print(group, tp.topic, tp.partition, cur, high, max(0, high - cur), m.member_id, host, m.client_id)
consumer.close()
PYEOF
}
owner_of_partition() {
    # $1 = partition, $2 = describe_group output, $3 = topic. Phase 5.6
    # Item 1: must filter by topic now - every tenant's alerts topic has
    # its own partitions 0..N, so partition number alone is ambiguous
    # once this group subscribes to more than one topic.
    echo "$2" | awk -v p="$1" -v t="$3" '$2 == t && $3 == p { print $8 }' | head -1 | tr -d '/'
}

# Produces one real sshd alert through the tenant's own per-tenant topic.
# args: tenant agent src_ip rule_groups_csv alert_id_suffix
produce_alert() {
    "$PY_CORRELATE" - "$KAFKA_BOOTSTRAP" "$1" "$2" "$3" "$4" "$5" <<'PYEOF'
import json, os, sys, time
sys.path.insert(0, os.path.join("..", "..", "shadowtracer", "ingest"))
from confluent_kafka import Producer
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env

bootstrap, tenant, agent, src_ip, groups_csv, suffix = sys.argv[1:7]
groups = groups_csv.split(",")

alert = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
    "id": f"{agent}.{suffix}",
    "rule": {"id": "5710", "level": 5, "description": "test", "groups": groups},
    "agent": {"id": agent, "name": agent, "ip": "172.28.0.99"},
    "manager": {"name": "shadowtracer-worker1"},
    "cluster": {"node": "worker1"},
    "data": {"srcip": src_ip},
    "decoder": {"name": "sshd"},
    "location": "/var/log/auth.log",
    "full_log": "test",
}
producer = Producer({"bootstrap.servers": bootstrap, **kafka_client_config_from_env()})
producer.produce(f"shadowtracer.t.{tenant}.alerts", key=agent.encode(),
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

# A dedicated throwaway tenant for every section below EXCEPT the real-lab-
# tenant warm-up read in section 2 (deliberately real data, creates nothing -
# see that section's own comment). incidents, campaigns,
# campaign_incidents, incident_alerts, and sequence_progress all have a
# plain tenant_key STRING column with no foreign key into `tenants`
# (confirmed against the schema) - a real tenants row was never needed
# for those tables, only to log in through the actual /auth/login API
# (which only the separate rare_tenant below, section 2's override test,
# ever does). Cleanup below deletes by this exact tenant_key/tenant_id
# across every table, in FK-safe order - no agent_id LIKE patterns,
# which is what let a sequence-test incident's campaign link slip
# through cleanup once already (see the cleanup section's own comment,
# and PHASE3_DATA_PLATFORM.md's incident writeup).
#
# Phase 5.6 Item 1: a real tenants row IS now needed regardless, even
# without logging in - Phase 5C Step 0's tenant_cache.is_known() check
# (writer.py and shadowtracer_correlate/consumer.py) rejects any event
# for a tenant_key that isn't in `tenants` at all, dead-lettering it as
# unknown_tenant - this script's events would have silently never
# become incidents without this row (a real, pre-existing gap this
# comment's "no tenants row needed" claim predates, not something Item 1
# introduced). A Kafka topic pair is ALSO now needed per tenant
# (create-kafka-topics.sh), since Item 1 topics are provisioned
# explicitly, never auto-created.
VERIFY_TENANT_KEY="verify-$(date +%s)-${RANDOM}"
psql_exec "INSERT INTO tenants (name, tenant_key) VALUES ('verify-tenant', '$VERIFY_TENANT_KEY');" >/dev/null
./create-kafka-topics.sh "$VERIFY_TENANT_KEY" >/dev/null

echo "=== Phase 5B VERIFY ==="
echo
echo "--- 1. Campaign linking: brute force repeated twice from one IP within 24h -> ONE campaign, 2 incidents ---"
marker="camp$(date +%s)"
agent="camp-agent-${marker}"
ip_a="203.0.113.$((RANDOM % 200 + 10))"
# Phase 5.6 Item 1: was "% 55 + 210" (210-264) - an octet above 255 is
# invalid, and _actor_class() (fingerprint.py) silently falls through
# to "internal" for a source_ips list it can't parse at all (never
# raises), rather than "external" - found the hard way: this test's own
# "same fingerprint" check intermittently failed (~1 in 6 runs, whenever
# $RANDOM rolled an octet >= 256) because incident 3's IP was invalid,
# classified "internal" against incident 1's valid, genuinely-external
# IP. Real test-data bug, not a pipeline bug - 210-255 (46 values) stays
# in range.
ip_b="203.0.113.$((RANDOM % 46 + 210))"

produce_alert "$VERIFY_TENANT_KEY" "$agent" "$ip_a" "sshd,authentication_failed" "1"
# 25s, not 8s, for this FIRST produce only - VERIFY_TENANT_KEY's topic
# is brand new, and a pattern-subscribed consumer only discovers it on
# its next periodic metadata refresh (topic.metadata.refresh.interval.ms,
# 10s as of this item - see writer.py/consumer.py's own comment; measured
# up to 206s against the OLD 5-minute librdkafka default). Every later
# produce in this script targets an already-discovered topic, so keeps
# the original 8s.
sleep 25
close_sweep
id1="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$VERIFY_TENANT_KEY' AND agent_id = '$agent' ORDER BY id LIMIT 1")"
check "incident 1 closed" "[ -n \"$id1\" ]"

produce_alert "$VERIFY_TENANT_KEY" "$agent" "$ip_a" "sshd,authentication_failed" "2"
sleep 8
close_sweep
id2="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$VERIFY_TENANT_KEY' AND agent_id = '$agent' AND id != $id1 ORDER BY id LIMIT 1")"
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

produce_alert "$VERIFY_TENANT_KEY" "$agent" "$ip_b" "sshd,authentication_failed" "3"
sleep 8
close_sweep
id3="$(psql_query "SELECT id FROM incidents WHERE tenant_key = '$VERIFY_TENANT_KEY' AND agent_id = '$agent' AND id NOT IN ($id1, $id2) ORDER BY id LIMIT 1")"
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
echo "real lab tenant's current warm-up status (this used to always be incomplete when this script was first written - the real lab tenant has since aged past it for real, through months of this project's own testing, so both outcomes are handled below rather than assuming one):"
login_resp="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/auth/login \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"$SMOKE_TEST_ADMIN_EMAIL\",\"password\":\"$SMOKE_TEST_ADMIN_PASSWORD\"}")"
lab_token="$(echo "$login_resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')"
lab_warmup="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/api/rare-pattern-warmup-status -H "Authorization: Bearer $lab_token")"
echo "$lab_warmup"
lab_complete="$(echo "$lab_warmup" | python3 -c 'import sys,json; print(json.load(sys.stdin)["complete"])')"
if [ "$lab_complete" = False ]; then
    check "real lab tenant has not finished warm-up" "[ \"$lab_complete\" = False ]"
    check "no rare-pattern flags during warm-up (real lab tenant)" \
        "[ \"$(psql_query "SELECT count(*) FROM incidents WHERE tenant_key = '$TENANT_KEY' AND rare_pattern_flag = true")\" = 0 ]"
else
    echo "real lab tenant is past warm-up for real (not this script's concern - the fresh-tenant case right below exercises the still-incomplete guard directly, with a known starting point)."
fi

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
./create-kafka-topics.sh "$rare_tenant_key" >/dev/null

psql_exec "INSERT INTO tenant_alert_settings (tenant_key, rare_alert_warmup_days, rare_alert_warmup_min_incidents) VALUES ('$rare_tenant_key', 0, 1);" >/dev/null

rare_email="rare-${rare_marker}@example.com"
rare_login="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/auth/login \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"$rare_email\",\"password\":\"VerifyRarePass123!\"}")"
rare_token="$(echo "$rare_login" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')"

rare_agent="rare-agent-${rare_marker}"
produce_alert "$rare_tenant_key" "$rare_agent" "203.0.113.90" "sshd,authentication_failed,recon" "1"
# 25s - same reason as VERIFY_TENANT_KEY's first produce above:
# rare_tenant_key's topic is also brand new at this point.
sleep 25
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
print(row['rare_pattern_flag'], row['prior_occurrences'])
")"
check "never-seen fingerprint gets a rare flag with occurrence count 0" "[ \"$rare_flag\" = 'True 0' ]"

echo
echo "--- 3. Sequence detection: fires once, replay-safe, survives a real correlator crash ---"
seq_marker="seq$(date +%s)"
seq_agent="seqv-agent-${seq_marker}"
seq_ip="203.0.113.$((RANDOM % 50 + 150))"

probe_partition="$("$PY_CORRELATE" - "$KAFKA_BOOTSTRAP" "$VERIFY_TENANT_KEY" "${seq_agent}-probe" <<'PYEOF'
import json, os, sys, time
sys.path.insert(0, os.path.join("..", "..", "shadowtracer", "ingest"))
from confluent_kafka import Producer
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
bootstrap, tenant, agent = sys.argv[1:4]
producer = Producer({"bootstrap.servers": bootstrap, **kafka_client_config_from_env()})
result = {}
def on_delivery(err, msg):
    if err is None:
        result["partition"] = msg.partition()
alert = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()), "id": f"{agent}.probe",
         "rule": {"id": "5710", "level": 5, "description": "probe", "groups": ["sshd"]},
         "agent": {"id": agent, "name": agent, "ip": "172.28.0.99"}, "manager": {"name": "shadowtracer-worker1"},
         "cluster": {"node": "worker1"}, "data": {"srcip": "1.1.1.1"}, "decoder": {"name": "sshd"},
         "location": "x", "full_log": "x"}
producer.produce(f"shadowtracer.t.{tenant}.alerts", key=agent.encode(), value=json.dumps(alert).encode(),
                  headers=[("tenant_id", tenant.encode())], on_delivery=on_delivery)
producer.flush(10)
print(result.get("partition", -1))
PYEOF
)"
owner_ip="$(owner_of_partition "$probe_partition" "$(describe_group)" "shadowtracer.t.${VERIFY_TENANT_KEY}.alerts")"
if [ "$owner_ip" = "$C1_IP" ]; then victim_name="$C1_NAME"; victim_ip="$C1_IP"; else victim_name="$C2_NAME"; victim_ip="$C2_IP"; fi
echo "sequence test agent's partition ($probe_partition) is owned by $victim_name"

produce_alert "$VERIFY_TENANT_KEY" "$seq_agent" "$seq_ip" "sshd,authentication_failed" "step0"
sleep 5
echo "killing $victim_name (docker kill) between step 0 and step 1..."
docker kill "$victim_name" >/dev/null

produce_alert "$VERIFY_TENANT_KEY" "$seq_agent" "$seq_ip" "sshd,authentication_success" "step1"

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
echo "--- replay safety: a fresh dedicated consumer group reading from this run's own messages must not double-fire ---"
replay_marker="replay$(date +%s)"
replay_agent="replayv-agent-${replay_marker}"
replay_ip="203.0.113.$((RANDOM % 50 + 1))"
replay_group="verify-replay-$(date +%s)"

# Phase 5.6 Item 1 SIMPLIFIES this: VERIFY_TENANT_KEY (and so its topic,
# shadowtracer.t.<VERIFY_TENANT_KEY>.alerts) is freshly generated THIS
# run (date +%s + $RANDOM) and never reused - the topic has no prior
# history by construction, so a fresh consumer group reading from
# earliest sees ONLY this run's own messages. No pre-seeding needed any
# more - this used to matter a lot (2026-10-08: replaying from earliest
# against the old SHARED shadowtracer.events.raw topic reprocessed every
# past run's alerts too) specifically because every run shared one
# topic; per-tenant topics remove that failure mode structurally, not
# just procedurally. See PHASE3_DATA_PLATFORM.md's follow-up entry for
# the incident this used to guard against.

produce_alert "$VERIFY_TENANT_KEY" "$replay_agent" "$replay_ip" "sshd,authentication_failed" "step0"
sleep 2
produce_alert "$VERIFY_TENANT_KEY" "$replay_agent" "$replay_ip" "sshd,authentication_success" "step1"

deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    first_fire="$(ch_query "SELECT uniqExact(completing_alert_id) FROM shadowtracer.sequence_firings WHERE agent_id = '$replay_agent'")"
    [ "$first_fire" = 1 ] && break
    sleep 2
done
check "fresh sequence fires once on first processing" "[ \"$first_fire\" = 1 ]"

echo "starting a temporary, isolated consumer group (pre-seeded to this run's own messages, not the whole topic) to replay and confirm it doesn't double-fire - never the live shadowtracer-correlate group, this doesn't touch its offsets at all..."
"$PY_CORRELATE" - "$DATABASE_URL_APP" "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" "$replay_group" <<'PYEOF'
import sys, threading, time, traceback
sys.path.insert(0, "../../shadowtracer/correlate")
sys.path.insert(0, "../../shadowtracer/ingest")
from shadowtracer_correlate.consumer import run
from shadowtracer_correlate.metrics import Metrics
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
import clickhouse_connect

database_url, ch_user, ch_password, group_id = sys.argv[1:5]
ch = clickhouse_connect.get_client(host="127.0.0.1", port=8123, username=ch_user, password=ch_password, database="shadowtracer")
stop_flag = threading.Event()
started_flag = threading.Event()

def _run():
    try:
        run(
            bootstrap_servers="127.0.0.1:9094",
            group_id=group_id, database_url=database_url,
            metrics=Metrics(), stop_flag=stop_flag, started_flag=started_flag,
            ch_client=ch, clickhouse_database="shadowtracer",
            sequences_dir="../../shadowtracer/correlate/sequences",
            kafka_client_config=kafka_client_config_from_env(),
        )
    except Exception:
        traceback.print_exc()
        started_flag.set()  # unblock the wait below so the failure is visible, not silently swallowed

t = threading.Thread(target=_run, daemon=True)
t.start()
if not started_flag.wait(timeout=10):
    print("REPLAY CONSUMER NEVER STARTED", file=sys.stderr)
time.sleep(15)  # this run's own 2 messages only now (pre-seeded offsets above), not the whole topic
stop_flag.set()
t.join(timeout=10)
print("replay consumer drained")
PYEOF

replay_fire_count="$(ch_query "SELECT uniqExact(completing_alert_id) FROM shadowtracer.sequence_firings WHERE agent_id = '$replay_agent'")"
check "replaying this run's own messages from a fresh, pre-seeded group does not fire it twice" "[ \"$replay_fire_count\" = 1 ]"

echo
echo "--- cleanup: removing this run's VERIFY data ---"
# By tenant_key/tenant_id alone, across every table, in FK-safe order -
# never by agent_id name pattern. A name-pattern filter has to be kept in
# sync, independently, at every DELETE that uses one - found the hard way
# (2026-10-08, this same run, before this rewrite): campaign_incidents'
# pattern list had only 2 of the 4 prefixes incidents' own DELETE used,
# missing a sequence-test incident's campaign link, which made the
# incidents DELETE hit a real FK violation and roll back this whole batch
# (psql -c runs multi-statement as one transaction). A tenant_key is exact
# and generated fresh every run (VERIFY_TENANT_KEY, rare_tenant_key) - no
# list to drift out of sync, and no risk of ever touching the real lab
# tenant's own campaigns (the previous version's campaigns DELETE scoped
# by tenant_key IN ($TENANT_KEY, ...) came uncomfortably close to that).
psql_exec "
DELETE FROM campaign_incidents WHERE incident_id IN (
  SELECT id FROM incidents WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')
);
DELETE FROM incident_alerts WHERE incident_id IN (
  SELECT id FROM incidents WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')
);
DELETE FROM incidents WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key');
DELETE FROM campaigns WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key');
DELETE FROM sequence_progress WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key');
DELETE FROM fingerprint_verdicts WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key');
DELETE FROM fingerprints WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key');
DELETE FROM tenant_alert_settings WHERE tenant_key = '$rare_tenant_key';
DELETE FROM refresh_tokens WHERE user_id IN (
  SELECT id FROM users WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_key = '$rare_tenant_key')
);
DELETE FROM users WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_key = '$rare_tenant_key');
DELETE FROM tenants WHERE tenant_key = '$rare_tenant_key';
-- Phase 5.6 Item 1: VERIFY_TENANT_KEY's own tenants row was never
-- deleted here at all (found the hard way: its name column is the
-- fixed literal 'verify-tenant', not unique per run, so a prior run's
-- never-cleaned-up row made every subsequent run's own INSERT fail on
-- that unique constraint, with the INSERT's error silently swallowed
-- by its own >/dev/null - every event then dead-lettered as
-- unknown_tenant for the rest of the run, which is what every one of
-- this script's closed/campaign/sequence checks were actually
-- failing on, not a real pipeline bug).
DELETE FROM tenants WHERE tenant_key = '$VERIFY_TENANT_KEY';
" >/dev/null
ch_query "ALTER TABLE shadowtracer.sequence_firings DELETE WHERE tenant_id = '$VERIFY_TENANT_KEY'"
ch_query "ALTER TABLE shadowtracer.events DELETE WHERE tenant_id IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')"

echo "--- proving cleanup left zero rows for this run's tenants ---"
leftover_pg="$(psql_query "
SELECT
  (SELECT count(*) FROM incidents WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM campaigns WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM campaign_incidents WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM incident_alerts WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM sequence_progress WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM fingerprint_verdicts WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM fingerprints WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
  (SELECT count(*) FROM tenant_alert_settings WHERE tenant_key = '$rare_tenant_key') +
  (SELECT count(*) FROM tenants WHERE tenant_key IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key'))
")"
check "zero leftover Postgres rows for this run's tenant(s)" "[ \"$leftover_pg\" = 0 ]"

# ALTER TABLE ... DELETE is an asynchronous mutation in ClickHouse - found
# the hard way, this same rewrite: querying right after issuing it can
# still see the old rows until the mutation actually runs. Poll instead
# of asserting once.
leftover_ch=-1
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    leftover_ch="$(ch_query "
    SELECT
      (SELECT count() FROM shadowtracer.events WHERE tenant_id IN ('$VERIFY_TENANT_KEY', '$rare_tenant_key')) +
      (SELECT count() FROM shadowtracer.sequence_firings WHERE tenant_id = '$VERIFY_TENANT_KEY')
    ")"
    [ "$leftover_ch" = 0 ] && break
    sleep 2
done
check "zero leftover ClickHouse rows for this run's tenant(s)" "[ \"$leftover_ch\" = 0 ]"

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "VERIFY-PHASE5B: PASS"
else
    echo "VERIFY-PHASE5B: FAIL"
fi
exit "$fail"
