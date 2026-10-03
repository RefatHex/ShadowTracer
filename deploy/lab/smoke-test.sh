#!/usr/bin/env bash
# Step 4 smoke test: quick automated check that the lab comes up and the
# cluster/agent topology is correct - NOT a re-run of every Step 3 capability
# (those were verified manually and are one-time proofs, see
# shadowtracer/docs/PHASE1_FINDINGS.md). This only checks structural health:
# does "docker compose up" produce 3 healthy manager nodes, a formed cluster,
# and the agents we expect to be Active.
#
# Run from deploy/lab/: ./smoke-test.sh
set -uo pipefail
cd "$(dirname "$0")"

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
docker compose up -d

# Only wait on the services expected to reach healthy. agent-rocky-1/2 have a
# known, documented glibc bug (PHASE1_FINDINGS.md Step 2) and never go
# healthy - that's not a smoke-test regression, so --wait (which waits on
# every service) would always time out here.
for svc in wazuh-master wazuh-worker1 wazuh-worker2 agent-ubuntu-1 agent-ubuntu-2 \
    shipper-worker1 shipper-worker2 writer-1 writer-2; do
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

MASTER=shadowtracer-lab-wazuh-master-1

echo "--- cluster ---"
cluster_out="$(docker exec "$MASTER" /var/ossec/bin/cluster_control -l)"
echo "$cluster_out"
check "master in cluster_control -l" "echo \"\$cluster_out\" | grep -q '^master '"
check "worker1 in cluster_control -l" "echo \"\$cluster_out\" | grep -q '^worker1 '"
check "worker2 in cluster_control -l" "echo \"\$cluster_out\" | grep -q '^worker2 '"

echo "--- agents ---"
agent_out="$(docker exec "$MASTER" /var/ossec/bin/agent_control -l)"
echo "$agent_out"
# Only the two Ubuntu agents are expected Active - Rocky agents have a known,
# documented glibc bug (PHASE1_FINDINGS.md, Step 2) and are not a smoke-test
# regression on their own.
check "agent-ubuntu-1 Active" "echo \"\$agent_out\" | grep agent-ubuntu-1 | grep -q Active"
check "agent-ubuntu-2 Active" "echo \"\$agent_out\" | grep agent-ubuntu-2 | grep -q Active"

echo "--- console (Step 7) ---"
if [ -f .env ]; then
    set -a; source .env; set +a
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
# wait loop above), the alert simply never arrives and this fails. Needs
# SMOKE_TEST_ADMIN_EMAIL/PASSWORD in .env for an admin user already
# created via `python cli.py create-admin` - this script never creates one
# itself (no default admin, Step 2).
if [ -z "${SMOKE_TEST_ADMIN_EMAIL:-}" ] || [ -z "${SMOKE_TEST_ADMIN_PASSWORD:-}" ]; then
    echo "SKIP: end-to-end alert test (set SMOKE_TEST_ADMIN_EMAIL/PASSWORD in .env - create that user first with: cd ../../shadowtracer/console/backend && python cli.py create-admin --tenant lab --email <email>)"
else
    echo "--- end-to-end: login, SSH brute force, alert through the API ---"
    login_resp="$(curl -sk --resolve localhost:8443:127.0.0.1 https://localhost:8443/auth/login \
        -X POST -H "Content-Type: application/json" \
        -d "{\"email\":\"$SMOKE_TEST_ADMIN_EMAIL\",\"password\":\"$SMOKE_TEST_ADMIN_PASSWORD\"}")"
    access_token="$(echo "$login_resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)"

    if [ -z "$access_token" ]; then
        echo "FAIL: could not log in as $SMOKE_TEST_ADMIN_EMAIL ($login_resp)"
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

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "SMOKE TEST: PASS"
else
    echo "SMOKE TEST: FAIL"
fi
exit "$fail"
