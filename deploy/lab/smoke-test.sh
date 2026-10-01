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
for svc in wazuh-master wazuh-worker1 wazuh-worker2 agent-ubuntu-1 agent-ubuntu-2; do
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

echo "---"
if [ "$fail" -eq 0 ]; then
    echo "SMOKE TEST: PASS"
else
    echo "SMOKE TEST: FAIL"
fi
exit "$fail"
