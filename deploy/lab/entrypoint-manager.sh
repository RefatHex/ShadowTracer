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

    # authd: require a password for enrollment (default ships use_password=no)
    sed -i 's:<use_password>no</use_password>:<use_password>yes</use_password>:' "$OSSEC_CONF"
    echo -n "${ENROLL_PASSWORD}" > /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
    chown root:wazuh /var/ossec/etc/authd.pass || true
fi

# Step 3 item 14: enable the raw event archive (off by default) so we can
# measure the archives.json-to-alerts.json size ratio over a capture window.
sed -i -e 's:<logall>no</logall>:<logall>yes</logall>:' \
       -e 's:<logall_json>no</logall_json>:<logall_json>yes</logall_json>:' \
       "$OSSEC_CONF"

# API: bind all interfaces, raise the request rate limit for lab load-testing.
API_YAML=/var/ossec/api/configuration/api.yaml
if [ -f "$API_YAML" ] && ! grep -q "^host:" "$API_YAML"; then
    { echo "host: ['0.0.0.0']"; echo "access:"; echo "  max_request_per_minute: 99999"; } >> "$API_YAML"
fi

/var/ossec/bin/wazuh-control start

exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/cluster.log /var/ossec/logs/api.log 2>/dev/null
