#!/usr/bin/env bash
# Runtime configuration for the shadowtracer-lab manager image. Applied to
# the INSTALLED copy of ossec.conf inside the container/volume, never to the
# repo's tracked etc/ossec.conf.
set -euo pipefail

CLUSTER_NODE_TYPE="${CLUSTER_NODE_TYPE:-worker}"
CLUSTER_NODE_NAME="${CLUSTER_NODE_NAME:-worker-1}"
CLUSTER_KEY="${CLUSTER_KEY:?CLUSTER_KEY is required}"
CLUSTER_MASTER_NAME="${CLUSTER_MASTER_NAME:-wazuh-master}"
ENROLL_PASSWORD="${ENROLL_PASSWORD:?ENROLL_PASSWORD is required}"

OSSEC_CONF=/var/ossec/etc/ossec.conf

# The installed ossec.conf already ships a <cluster> block with placeholder
# values (empty <key>, node_name=node01, <node>NODE_IP</node>, disabled=yes)
# - it's never absent, so patch those placeholders in place rather than
# guarding on "<cluster> missing" (which never happens and silently no-ops).
if grep -q "<node>NODE_IP</node>" "$OSSEC_CONF"; then
    sed -i \
        -e "s:<node_name>node01</node_name>:<node_name>${CLUSTER_NODE_NAME}</node_name>:" \
        -e "s:<node_type>master</node_type>:<node_type>${CLUSTER_NODE_TYPE}</node_type>:" \
        -e "s:<key></key>:<key>${CLUSTER_KEY}</key>:" \
        -e "s:<node>NODE_IP</node>:<node>${CLUSTER_MASTER_NAME}</node>:" \
        -e "s:<disabled>yes</disabled>:<disabled>no</disabled>:" \
        "$OSSEC_CONF"

    # Phase 3 DECISIONS.md: pin hide_cluster_info to "no". The installed
    # template already ships <hidden>no</hidden> in the cluster block, but
    # pin it explicitly (covering both "tag present but yes" and "tag
    # missing") so this doesn't silently regress if a future upstream
    # template changes the default - alert identity in Phase 3 depends on
    # cluster.node always being present.
    if grep -q "<hidden>" "$OSSEC_CONF"; then
        sed -i 's:<hidden>yes</hidden>:<hidden>no</hidden>:' "$OSSEC_CONF"
    else
        sed -i '/<\/cluster>/i\    <hidden>no</hidden>' "$OSSEC_CONF"
    fi

    # authd: require a password for enrollment (default ships use_password=no)
    sed -i 's:<use_password>no</use_password>:<use_password>yes</use_password>:' "$OSSEC_CONF"
    echo -n "${ENROLL_PASSWORD}" > /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
    chown root:wazuh /var/ossec/etc/authd.pass || true
fi

# Step 3 item 14 (data volume) temporarily flipped <logall>/<logall_json> on
# here to measure the archives.json-to-alerts.json ratio under real agent
# activity - that measurement is done (see PHASE1_FINDINGS.md) and the raw
# event archive is back off by default, matching ossec.conf's shipped default.

# API: bind all interfaces, raise the request rate limit for lab load-testing.
API_YAML=/var/ossec/api/configuration/api.yaml
if [ -f "$API_YAML" ] && ! grep -q "^host:" "$API_YAML"; then
    { echo "host: ['0.0.0.0']"; echo "access:"; echo "  max_request_per_minute: 99999"; } >> "$API_YAML"
fi

# Phase 3: /var/ossec/logs/alerts is bind-mounted from the host (see
# docker-compose.yml) so shadowtracer/ingest's shipper can tail alerts.json
# directly, one shipper process per manager node. Docker creates a fresh
# bind-mount host directory as root:root, which wazuh-analysisd (running
# as wazuh:wazuh) can't write into - chown it before starting daemons.
if mountpoint -q /var/ossec/logs/alerts 2>/dev/null; then
    chown wazuh:wazuh /var/ossec/logs/alerts
    chmod 755 /var/ossec/logs/alerts
    # The shipper runs on the host as a different uid than the wazuh user
    # inside this container, so alerts.json itself also needs to stay
    # world-readable for it - lab-only, a real deployment runs the shipper
    # as a sidecar sharing the manager's uid/mount instead of across a
    # host/container uid boundary.
    (while true; do chmod o+r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true; sleep 2; done) &
fi

/var/ossec/bin/shadowtracer-control start

exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/cluster.log /var/ossec/logs/api.log 2>/dev/null
