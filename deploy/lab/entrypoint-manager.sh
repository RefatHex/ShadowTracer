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

if ! grep -q "<cluster>" "$OSSEC_CONF"; then
    cluster_block=$(cat <<EOF
  <cluster>
    <name>shadowtracer-lab</name>
    <node_name>${CLUSTER_NODE_NAME}</node_name>
    <node_type>${CLUSTER_NODE_TYPE}</node_type>
    <key>${CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>${CLUSTER_MASTER_NAME}</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
EOF
)
    awk -v block="$cluster_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
    mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"

    # authd: require a password for enrollment (default ships use_password=no)
    sed -i 's:<use_password>no</use_password>:<use_password>yes</use_password>:' "$OSSEC_CONF"
    echo -n "${ENROLL_PASSWORD}" > /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
    chown root:wazuh /var/ossec/etc/authd.pass || true
fi

# API: bind all interfaces, raise the request rate limit for lab load-testing.
API_YAML=/var/ossec/api/configuration/api.yaml
if [ -f "$API_YAML" ] && ! grep -q "^host:" "$API_YAML"; then
    { echo "host: ['0.0.0.0']"; echo "max_request_per_minute: 99999"; } >> "$API_YAML"
fi

/var/ossec/bin/wazuh-control start

exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/cluster.log /var/ossec/logs/api.log 2>/dev/null
