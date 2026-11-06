#!/usr/bin/env bash
# Step 4 smoke test: quick automated check that the lab comes up and the
# cluster/agent topology is correct - NOT a re-run of every Step 3 capability
# (those were verified manually and are one-time proofs, see
# shadowtracer/docs/PHASE1_FINDINGS.md). This only checks structural health:
# does "docker compose up" produce 3 healthy manager nodes, a formed cluster,
# and the agents we expect to be Active.
#
# Run from deploy/lab/: ./smoke-test.sh
#
# NOT included here: verify-correlator-chaos.sh (Phase 5A hardening) -
# real `docker kill` on a live correlate-1/correlate-2 container to prove
# the correlation engine survives a real crash mid-attack, plus the real
# correlator consumer group's partition split/rebalance. Kept separate
# deliberately (not bundled into routine smoke-test runs) since it
# disrupts a real running service for ~60-90s each time, which a quick
# structural-health check shouldn't do by default. Run it on its own:
#   ./verify-correlator-chaos.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1
if [ -f .env ]; then
    set -a; source .env; set +a
fi
# Phase 5.6 Item 1: admin (super-user, bypasses ACLs) - the one Python
# Kafka client in this script (dlt_watermark_sum) is an operator
# diagnostic, not a real pipeline component.
export KAFKA_SECURITY_PROTOCOL=SASL_SSL
export KAFKA_SASL_USERNAME=admin
export KAFKA_SASL_PASSWORD="${KAFKA_ADMIN_PASSWORD:-}"
KAFKA_SSL_CA_LOCATION="$(pwd)/kafka-certs/ca.crt"; export KAFKA_SSL_CA_LOCATION
# Rebrand Pass C prep: one setting for the install dir, default unchanged -
# see docs/design/REBRAND_PASS_C.md.
SHADOWTRACER_INSTALL_DIR="${SHADOWTRACER_INSTALL_DIR:-/var/ossec}"

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

echo "--- bringing up the lab ---"
# Kafka first, alone: each tenant's topic pair must be explicitly
# provisioned (create-kafka-topics.sh - 3 partitions each, Phase 5.6
# Item 1) before shipper/writer start and race it via
# auto.create.topics.enable's implicit 1-partition default.
docker compose up -d kafka
# Phase 5.6 Item 1: kafka's own healthcheck already authenticates as
# admin (docker-compose.yml) - waiting on docker's own health status
# instead of a raw unauthenticated kafka-topics.sh call, which the
# SASL_SSL broker now refuses outright (found the hard way: the old
# unauthenticated check just hung until this script's own 60s timeout).
waited=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' shadowtracer-lab-kafka-1 2>/dev/null)" = "healthy" ]; do
    sleep 2
    waited=$((waited + 2))
    if [ "$waited" -ge 120 ]; then
        echo "FAIL: kafka did not become healthy within 120s"
        exit 1
    fi
done
./create-kafka-topics.sh

# ClickHouse next, alone: the events/rollup schema must be explicitly
# applied (create-clickhouse-schema.sh) before shipper/writer start and
# find no events table at all on a from-scratch bring-up.
# 6.1c follow-up: the second ClickHouse replica, worker1/worker2 and their shippers
# run only in the "ha" compose profile. Default: the profile that is up.
# HA=1 ./smoke-test.sh (or a running ch-clickhouse-2) checks the "ha" lab instead.
if [ "${HA:-}" = "1" ] || docker ps -q -f name=^shadowtracer-lab-ch-clickhouse-2-1$ -f status=running | grep -q .; then
    HA=1; set -a; . ./ha.env; set +a
else
    HA=0
fi
echo "--- profile: $([ "$HA" = 1 ] && echo ha || echo default) ---"
CH_CONTAINERS="shadowtracer-lab-ch-clickhouse-1-1"
[ "$HA" = 1 ] && CH_CONTAINERS="$CH_CONTAINERS shadowtracer-lab-ch-clickhouse-2-1"
docker compose up -d ch-keeper ch-clickhouse-1 $([ "$HA" = 1 ] && echo ch-clickhouse-2)
waited=0
until docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client \
    --query "SELECT 1" >/dev/null 2>&1; do
    sleep 2
    waited=$((waited + 2))
    if [ "$waited" -ge 90 ]; then
        echo "FAIL: clickhouse did not become ready within 90s"
        exit 1
    fi
done
./create-clickhouse-schema.sh

docker compose up -d

# Only wait on the services expected to reach healthy. agent-rocky-1/2 have a
# known, documented glibc bug (PHASE1_FINDINGS.md Step 2) and never go
# healthy - that's not a smoke-test regression, so --wait (which waits on
# every service) would always time out here.
HA_SERVICES=""
[ "$HA" = 1 ] && HA_SERVICES="shadowtracer-worker1 shadowtracer-worker2 shipper-worker1 shipper-worker2"
for svc in shadowtracer-master shadowtracer-worker-test agent-ubuntu-1 agent-ubuntu-2 \
    shipper-master shipper-worker-test writer-1 writer-2 \
    correlate-1 correlate-2 closer-1 closer-2 $HA_SERVICES; do
    cid="$(docker compose ps -q "$svc")"
    waited=0
    while [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid")" != "healthy" ]; do
        sleep 2
        waited=$((waited + 2))
        if [ "$waited" -ge 180 ]; then
            echo "FAIL: $svc did not reach healthy within 180s"
            fail=1
            break
        fi
    done
done
if [ "$fail" -ne 0 ]; then
    exit 1
fi

MASTER=shadowtracer-lab-shadowtracer-master-1

echo "--- cluster ---"
cluster_out="$(docker exec "$MASTER" "${SHADOWTRACER_INSTALL_DIR}/bin/cluster_control" -l)"
echo "$cluster_out"
check "master in cluster_control -l" "echo \"\$cluster_out\" | grep -q '^master '"
if [ "$HA" = 1 ]; then
    check "worker1 in cluster_control -l" "echo \"\$cluster_out\" | grep -q '^worker1 '"
    check "worker2 in cluster_control -l" "echo \"\$cluster_out\" | grep -q '^worker2 '"
fi
# Phase 6.1a: the test tenant's manager is its own single-node cluster
# (TENANCY.md option A) - never a member of the main tenant's cluster, which
# would sync the main tenant's client.keys/rules/lists onto it.
TEST_MGR=shadowtracer-lab-shadowtracer-worker-test-1
check "worker-test NOT in the main cluster" "! echo \"\$cluster_out\" | grep -q '^worker-test '"
test_cluster_out="$(docker exec "$TEST_MGR" "${SHADOWTRACER_INSTALL_DIR}/bin/cluster_control" -l)"
echo "$test_cluster_out"
check "worker-test is master of its own one-node cluster" \
    "echo \"\$test_cluster_out\" | grep -q '^worker-test  *master ' && [ \"\$(echo \"\$test_cluster_out\" | grep -vc '^NAME')\" = 1 ]"
check "test cluster has its own name" \
    "docker exec $TEST_MGR sed -n '/<cluster>/,/<\\/cluster>/p' ${SHADOWTRACER_INSTALL_DIR}/etc/ossec.conf | grep -q '<name>shadowtracer-test</name>'"

echo "--- agents ---"
agent_out="$(docker exec "$MASTER" "${SHADOWTRACER_INSTALL_DIR}/bin/agent_control" -l)"
echo "$agent_out"
test_agent_out="$(docker exec "$TEST_MGR" "${SHADOWTRACER_INSTALL_DIR}/bin/agent_control" -l)"
echo "$test_agent_out"
# Phase 6.1a: each agent is registered only with its own tenant's manager.
check "agent-ubuntu-1 not registered on the main master" "! echo \"\$agent_out\" | grep -q 'Name: agent-ubuntu-1,'"
check "agent-ubuntu-2 not registered on the test manager" "! echo \"\$test_agent_out\" | grep -q 'Name: agent-ubuntu-2,'"
# Only the two Ubuntu agents are expected Active - Rocky agents have a known,
# documented glibc bug (PHASE1_FINDINGS.md, Step 2) and are not a smoke-test
# regression on their own.
for a in agent-ubuntu-1 agent-ubuntu-2; do
    if [ "$a" = agent-ubuntu-1 ]; then a_out="$test_agent_out"; else a_out="$agent_out"; fi
    check "$a Active" "echo \"\$a_out\" | grep $a | grep -q Active"
    if ! echo "$a_out" | grep "$a" | grep -q Active; then
        # A recreated agent container has lost its client.keys and is refused
        # re-enrollment under its still-registered name (authd's default,
        # kept on purpose) - the fix is removing the old registration first.
        echo "  hint: if $a's container was recreated, run ./recreate-agent.sh $a"
        docker logs --tail 3 "shadowtracer-lab-$a-1" 2>&1 | sed 's/^/  agent log: /'
    fi
done

echo "--- ClickHouse replica health (dead-letter-ClickHouse incident, 2026-10-08) ---"
# The smoke test's own hostile-input check below only ever queried
# ch-clickhouse-1 and only ever checked row COUNTS, never is_readonly -
# see PHASE3_DATA_PLATFORM.md's incident writeup for why that let a
# replica stuck read-only go undetected. This checks is_readonly=0 and
# is_session_expired=0 for EVERY replicated table on BOTH replicas
# directly, every run, so a migration that leaves a replica in that
# state fails the very next smoke-test run instead of silently
# degrading durability until someone notices by accident.
for ch_container in $CH_CONTAINERS; do
    unhealthy="$(docker exec "$ch_container" clickhouse-client --query \
        "SELECT database, table, is_readonly, is_session_expired FROM system.replicas WHERE is_readonly OR is_session_expired" 2>&1)"
    if [ -n "$unhealthy" ]; then
        echo "FAIL: $ch_container has unhealthy replicated table(s):"
        echo "$unhealthy"
        fail=1
    else
        echo "PASS: $ch_container - every replicated table is_readonly=0, is_session_expired=0"
    fi
done

echo "--- console (Step 7) ---"

# Phase 5C Step 0, item 3: baseline, checked again at the very end of this
# script - the main lab tenant must receive zero rows from any of the test
# traffic this script generates (the SSH burst and the hostile-input
# batch below both now ship under TEST_TENANT_KEY, never TENANT_KEY).
main_tenant_incidents_before=0
if [ -n "${TENANT_KEY:-}" ]; then
    main_tenant_incidents_before="$(docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
        "SELECT count(*) FROM incidents WHERE tenant_key = '$TENANT_KEY'" | tr -d '[:space:]')"
fi

check "caddy reachable (TLS)" \
    "curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/health | grep -q '\"status\":\"ok\"'"
check "console readiness (Postgres/ClickHouse/Kafka all reachable)" \
    "curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/health/ready | grep -q '\"ready\":true'"

# End-to-end: log in, generate a real SSH brute force on agent-ubuntu-1,
# confirm the alert reaches /api/alerts within 30s - the walking skeleton's
# whole point (Phase 4 Step 7). The shipper/writer are compose services now
# (Phase 4 follow-up 2, not host processes) - this script starts nothing
# itself; if the pipeline isn't running (or isn't healthy - checked in the
# wait loop above), the alert simply never arrives and this fails.
#
# Phase 5C Step 0, item 3: agent-ubuntu-1 is pointed at the dedicated test
# manager (shadowtracer-worker-test), never worker1/worker2, so this burst's real
# alert lands in TEST_TENANT_KEY - logging in as the main lab tenant's
# admin would never see it. Needs TEST_TENANT_ADMIN_EMAIL/PASSWORD in .env
# for an admin already created via `python cli.py create-admin` - this
# script never creates one itself (no default admin, Step 2).
if [ -z "${TEST_TENANT_ADMIN_EMAIL:-}" ] || [ -z "${TEST_TENANT_ADMIN_PASSWORD:-}" ]; then
    echo "SKIP: end-to-end alert test (set TEST_TENANT_ADMIN_EMAIL/PASSWORD in .env - create that user first with: cd ../../shadowtracer/console/backend && python cli.py create-admin --tenant shadowtracer-lab-test --email <email>)"
else
    echo "--- end-to-end: login, SSH brute force, alert through the API ---"
    login_resp="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/auth/login \
        -X POST -H "Content-Type: application/json" \
        -d "{\"email\":\"$TEST_TENANT_ADMIN_EMAIL\",\"password\":\"$TEST_TENANT_ADMIN_PASSWORD\"}")"
    access_token="$(echo "$login_resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)"

    if [ -z "$access_token" ]; then
        echo "FAIL: could not log in as $TEST_TENANT_ADMIN_EMAIL ($login_resp)"
        fail=1
    else
        marker="smoketest$(date +%s)"
        docker exec shadowtracer-lab-agent-ubuntu-1-1 sh -c \
            "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 ${marker}@localhost true" \
            >/dev/null 2>&1 || true

        found=0
        for _ in $(seq 1 30); do
            alerts_resp="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/api/alerts \
                -H "Authorization: Bearer $access_token")"
            if echo "$alerts_resp" | grep -q "$marker"; then
                found=1
                break
            fi
            sleep 1
        done
        check "alert for $marker appears through /api/alerts within 30s" "[ \"$found\" = 1 ]"
    fi
fi

echo "--- hostile input: no single event may stop the pipeline ---"
# Injects a batch mixing 2 good events with 8 hostile ones - one per
# category the pipeline must survive without crashing (an invalid
# timestamp, an out-of-range timestamp, a missing required field, a wrong
# type, a 10 MB full_log, invalid UTF-8, deeply nested JSON, and an empty
# object) - straight into shipper-worker-test's real, tailed alerts.json,
# the same file Wazuh itself writes to. Proves: every good event still
# lands in ClickHouse and an incident, every bad one is dead-lettered (not
# silently dropped, not crashing anything), and no container restarts.
# Phase 5C Step 0, item 3: this used to inject into alerts-worker1 (the
# main lab tenant's manager) - moved to alerts-worker-test so this script
# never writes a single row into the main tenant's data.
hostile_marker="hostile$(date +%s)"
hostile_agent="hostile-agent-${hostile_marker}"

# uniqExact(identity), never count(): dead_letter_events is a
# ReplicatedReplacingMergeTree (Phase 5C Step 0) - it only collapses
# duplicate (tenant_id, component, source_location) rows at MERGE time,
# so a plain count() can overcount until a background merge (or an
# explicit OPTIMIZE ... FINAL) catches up. Confirmed for real running
# this same query before vs. after a forced OPTIMIZE ... FINAL on this
# exact table: count() read 448, uniqExact read 376 - only converged to
# 376 after the merge. Same idiom health.py's dead_letter_counts_per_tenant
# already uses, for the same reason.
DLT_COUNT_QUERY="SELECT uniqExact((tenant_id, component, source_location)) FROM shadowtracer.dead_letter_events"
dl_before="$(docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client --query "$DLT_COUNT_QUERY")"
dl_before2=0
[ "$HA" = 1 ] && dl_before2="$(docker exec shadowtracer-lab-ch-clickhouse-2-1 clickhouse-client --query "$DLT_COUNT_QUERY")"

dlt_watermark_sum() {
    # Phase 5.6 Item 1: this batch is injected via shipper-worker-test
    # (the test tenant), so its dead letters land on THAT tenant's own
    # dead-letter topic now, not one shared shadowtracer.events.dead-letter.
    ../../shadowtracer/ingest/.venv/bin/python3 -c "
import sys
sys.path.insert(0, '../../shadowtracer/ingest')
from confluent_kafka import Consumer, TopicPartition
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
consumer = Consumer({'bootstrap.servers': '127.0.0.1:9094', 'group.id': 'smoke-test-dlt-watermark', **kafka_client_config_from_env()})
topic = 'shadowtracer.t.${TEST_TENANT_KEY}.dead-letter'
md = consumer.list_topics(topic, timeout=10).topics[topic]
total = 0
for p in md.partitions:
    _, high = consumer.get_watermark_offsets(TopicPartition(topic, p), timeout=10)
    total += high
consumer.close()
print(total)
"
}
dlt_offset_before="$(dlt_watermark_sum)"

restart_counts_before=()
pipeline_services="shipper-worker-test shipper-master writer-1 writer-2 correlate-1 correlate-2"
[ "$HA" = 1 ] && pipeline_services="$pipeline_services shipper-worker2"
for svc in $pipeline_services; do
    cid="$(docker compose ps -q "$svc")"
    restart_counts_before+=("$(docker inspect -f '{{.RestartCount}}' "$cid")")
done

hostile_batch_file="$(mktemp)"
python3 - "$hostile_marker" "$hostile_agent" > "$hostile_batch_file" <<'PYEOF'
import json
import sys

marker, agent = sys.argv[1], sys.argv[2]


def good(suffix):
    return json.loads(json.dumps({
        "timestamp": "2026-10-04T12:00:00.000+0000",
        "rule": {"id": "5710", "level": 5, "description": "sshd failure", "groups": ["sshd"]},
        "agent": {"id": agent, "name": agent, "ip": "10.0.0.1"},
        "manager": {"name": "shadowtracer-worker-test"},
        "cluster": {"node": "worker-test"},
        "id": f"{marker}.good.{suffix}",
        "data": {"srcip": "9.9.9.9"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"Invalid user {marker} from 9.9.9.9",
    }))


lines = [json.dumps(good("1")), json.dumps(good("2"))]

missing_ts = good("missing-ts")
del missing_ts["timestamp"]
lines.append(json.dumps(missing_ts))

bad_ts = good("bad-ts")
bad_ts["timestamp"] = "2026-10-04T05:00:118.000+0000"  # seconds=118: not valid ISO8601
lines.append(json.dumps(bad_ts))

bad_month = good("bad-month")
bad_month["timestamp"] = "2026-13-01T00:00:00.000+0000"  # month=13: out of range
lines.append(json.dumps(bad_month))

lines.append("{}")  # empty object

wrong_type = good("wrong-type")
wrong_type["agent"] = "not-an-object"  # wrong type: breaks agent.get(...) before anything else even runs
lines.append(json.dumps(wrong_type))

huge = good("huge")
huge["full_log"] = "x" * (11 * 1024 * 1024)  # 10+ MB: exceeds Kafka's message.max.bytes
lines.append(json.dumps(huge))

# Deeply nested JSON: 20000 levels is past CPython's json decoder's own
# recursion limit (confirmed empirically: 5000 parses fine, 20000 cleanly
# raises RecursionError, never a C stack overflow/segfault) - exercises
# the same path a genuinely pathological payload would hit.
lines.append("[" * 20000 + "]" * 20000)

print("\n".join(lines))
PYEOF

# Invalid UTF-8 can't round-trip through the python heredoc's text stdout -
# appended separately, in raw bytes. Leading invalid bytes before any JSON
# quoting: errors="replace" turns them into U+FFFD rather than crashing the
# shipper's read loop, but the result still isn't valid JSON, so it fails
# downstream and gets dead-lettered same as anything else malformed (see
# shadowtracer/ingest/tests/test_shipper.py's identical construction).
printf '\xff\xfe{"bad": "invalid utf-8"}\n' >> "$hostile_batch_file"

n_lines="$(wc -l < "$hostile_batch_file")"
echo "injecting $n_lines lines (2 good + 8 hostile) into shipper-worker-test's real alerts.json..."
docker run --rm -i -v "$(pwd)/alerts-worker-test:/data" busybox sh -c 'cat >> /data/alerts.json' < "$hostile_batch_file"
rm -f "$hostile_batch_file"

good_count=0
dl_after=0
dl_after2=0
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    good_count="$(docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client \
        --query "SELECT count() FROM shadowtracer.events WHERE alert_id LIKE '${hostile_marker}.good.%'")"
    dl_after="$(docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client \
        --query "$DLT_COUNT_QUERY")"
    dl_after2=$((dl_before2 + 12))
    [ "$HA" = 1 ] && dl_after2="$(docker exec shadowtracer-lab-ch-clickhouse-2-1 clickhouse-client \
        --query "$DLT_COUNT_QUERY")"
    if [ "$good_count" = "2" ] && [ "$((dl_after - dl_before))" = "12" ] && [ "$((dl_after2 - dl_before2))" = "12" ]; then
        break
    fi
    sleep 1
done

check "both good events landed in ClickHouse" "[ \"$good_count\" = 2 ]"
check "all 12 dead-letter writes landed on ch-clickhouse-1 (4 shipper-stage + 8 from writer+correlator each independently dead-lettering the 4 that reach Kafka)" \
    "[ \"\$((dl_after - dl_before))\" = 12 ]"
if [ "$HA" = 1 ]; then
    check "all 12 dead-letter writes also landed on ch-clickhouse-2 (replica, not just the one this script used to only ever check - 2026-10-08 incident)" \
        "[ \"\$((dl_after2 - dl_before2))\" = 12 ]"
fi

# The ClickHouse-side checks above only prove the QUERYABLE copy. Durability
# comes from the Kafka dead-letter topic FIRST (see dead_letter.py) - this
# confirms that copy actually landed too, not just the ClickHouse side.
# Counted by offset delta, not by grepping for hostile_marker in the
# payload - 4 of the 8 hostile categories (the empty object, the deeply
# nested JSON, and invalid UTF-8) never contain the marker string at all,
# so content-matching undercounts; the topic's own offsets don't.
#
# Polled, not a single snapshot - found running this script several times
# in quick succession (2026-10-09): a single dlt_offset_after read right
# after the ClickHouse-side loop exits can occasionally observe the delta
# a beat before Kafka's own replication/ISR catches up under back-to-back
# load, a transient false FAIL with nothing wrong - the ClickHouse count
# above, taken at the same moment, was already correct every time this
# happened. Same fix shape as the other eventual-consistency polls in this
# script and verify-phase5b.sh.
dlt_offset_after=-1
dlt_deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$dlt_deadline" ]; do
    dlt_offset_after="$(dlt_watermark_sum)"
    [ "$((dlt_offset_after - dlt_offset_before))" = 12 ] && break
    sleep 2
done
check "all 12 dead-letter events also landed on the Kafka dead-letter topic (the durable copy, written before ClickHouse)" \
    "[ \"\$((dlt_offset_after - dlt_offset_before))\" = 12 ]"

incident_count="$(docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
    "SELECT alert_count FROM incidents WHERE agent_id = '${hostile_agent}'" | tr -d '[:space:]')"
check "an incident with both good alerts exists (agent_id=${hostile_agent})" "[ \"$incident_count\" = 2 ]"

restart_ok=1
i=0
for svc in $pipeline_services; do
    cid="$(docker compose ps -q "$svc")"
    now_count="$(docker inspect -f '{{.RestartCount}}' "$cid")"
    before_count="${restart_counts_before[$i]}"
    if [ "$now_count" != "$before_count" ]; then
        echo "FAIL: $svc restarted during the hostile-input batch ($before_count -> $now_count)"
        restart_ok=0
    fi
    i=$((i + 1))
done
check "no pipeline container restarted" "[ \"$restart_ok\" = 1 ]"

if [ -n "${TENANT_KEY:-}" ]; then
    main_tenant_incidents_after="$(docker exec shadowtracer-lab-postgres-1 env PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
        "SELECT count(*) FROM incidents WHERE tenant_key = '$TENANT_KEY'" | tr -d '[:space:]')"
    check "main lab tenant received zero new incidents from this run ($main_tenant_incidents_before -> $main_tenant_incidents_after)" \
        "[ \"$main_tenant_incidents_after\" = \"$main_tenant_incidents_before\" ]"
fi

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "SMOKE TEST: PASS"
else
    echo "SMOKE TEST: FAIL"
fi
exit "$fail"
