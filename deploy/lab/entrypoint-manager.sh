#!/usr/bin/env bash
# Runtime configuration for the shadowtracer-lab manager image. Applied to
# the INSTALLED copy of ossec.conf inside the container/volume, never to the
# repo's tracked etc/ossec.conf.
set -euo pipefail

CLUSTER_NODE_TYPE="${CLUSTER_NODE_TYPE:-worker}"
CLUSTER_NODE_NAME="${CLUSTER_NODE_NAME:-worker-1}"
CLUSTER_KEY="${CLUSTER_KEY:?CLUSTER_KEY is required}"
CLUSTER_MASTER_NAME="${CLUSTER_MASTER_NAME:-shadowtracer-master}"
# Phase 6.1a: one cluster per tenant (TENANCY.md option A) - the test
# tenant's manager sets its own name; the main tenant keeps "wazuh".
CLUSTER_NAME="${CLUSTER_NAME:-wazuh}"
ENROLL_PASSWORD="${ENROLL_PASSWORD:?ENROLL_PASSWORD is required}"
# Rebrand Pass C prep: one setting for the install dir, default unchanged
# (/var/ossec) - no path change yet, just removes the 41 scattered literal
# hardcodes across deploy/lab/ so a future change (Stage 4) touches one
# value instead of all of them. See docs/design/REBRAND_PASS_C.md.
SHADOWTRACER_INSTALL_DIR="${SHADOWTRACER_INSTALL_DIR:-/var/ossec}"

OSSEC_CONF="${SHADOWTRACER_INSTALL_DIR}/etc/ossec.conf"

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
    sed -i "/<cluster>/,/<\/cluster>/ s:<name>wazuh</name>:<name>${CLUSTER_NAME}</name>:" "$OSSEC_CONF"

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
    echo -n "${ENROLL_PASSWORD}" > "${SHADOWTRACER_INSTALL_DIR}/etc/authd.pass"
    chmod 640 "${SHADOWTRACER_INSTALL_DIR}/etc/authd.pass"
    chown root:wazuh "${SHADOWTRACER_INSTALL_DIR}/etc/authd.pass" || true

    # authd's same-name replacement policy is deliberately left at Wazuh's
    # defaults (<force> enabled, disconnected_time 1h, after_registration_time
    # 1h): a new enrollment may NOT take over the name of an agent that is
    # still active or only recently disconnected. With that check off,
    # anyone holding the shared enrollment password can re-enroll under a
    # live agent's name, get that agent's identity (and ID) re-keyed to
    # themselves, and from then on feed events and receive active responses
    # as that agent - while the real agent is silently cut off. The
    # password alone does not prevent that; this check is what does.
    # A lab agent container that is recreated loses its client.keys (no
    # volume) and is refused under that same rule - recreate agents with
    # deploy/lab/recreate-agent.sh, which removes the old registration on
    # the master first (manage_agents -r), instead of weakening authd here.
fi

# Load-test syslog input (test manager only; docker-compose.yml sets
# LOAD_TEST_SYSLOG_PORT on shadowtracer-worker-test and nowhere else).
# THROUGHPUT_BASELINE.md §2.1 used to add this block by hand, and it was
# lost on every recreate.
if [ -n "${LOAD_TEST_SYSLOG_PORT:-}" ] && ! grep -q "<port>${LOAD_TEST_SYSLOG_PORT}</port>" "$OSSEC_CONF"; then
    cat >> "$OSSEC_CONF" <<EOF
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>${LOAD_TEST_SYSLOG_PORT}</port>
    <protocol>udp</protocol>
    <allowed-ips>172.28.0.0/16</allowed-ips>
  </remote>
</ossec_config>
EOF
fi

# Same, over TCP (LOAD_TEST_SYSLOG_TCP_PORT): a reader that falls behind
# back-pressures the sender instead of the kernel dropping datagrams, so a
# load test can check sent == written exactly (OPTIMIZATION_BACKLOG T12).
# Wazuh refuses tcp,udp on one syslog block (remote-config.c:299-301).
if [ -n "${LOAD_TEST_SYSLOG_TCP_PORT:-}" ] && ! grep -q "<port>${LOAD_TEST_SYSLOG_TCP_PORT}</port>" "$OSSEC_CONF"; then
    cat >> "$OSSEC_CONF" <<EOF
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>${LOAD_TEST_SYSLOG_TCP_PORT}</port>
    <protocol>tcp</protocol>
    <allowed-ips>172.28.0.0/16</allowed-ips>
  </remote>
</ossec_config>
EOF
fi

# Step 3 item 14 (data volume) temporarily flipped <logall>/<logall_json> on
# here to measure the archives.json-to-alerts.json ratio under real agent
# activity - that measurement is done (see PHASE1_FINDINGS.md) and the raw
# event archive is back off by default, matching ossec.conf's shipped default.

# API: bind all interfaces, raise the request rate limit for lab load-testing.
API_YAML="${SHADOWTRACER_INSTALL_DIR}/api/configuration/api.yaml"
if [ -f "$API_YAML" ] && ! grep -q "^host:" "$API_YAML"; then
    { echo "host: ['0.0.0.0']"; echo "access:"; echo "  max_request_per_minute: 99999"; } >> "$API_YAML"
fi

# Phase 3: /var/ossec/logs/alerts is bind-mounted from the host (see
# docker-compose.yml) so shadowtracer/ingest's shipper can tail alerts.json
# directly, one shipper process per manager node. Docker creates a fresh
# bind-mount host directory as root:root, which wazuh-analysisd (running
# as wazuh:wazuh) can't write into - chown it before starting daemons.
if mountpoint -q "${SHADOWTRACER_INSTALL_DIR}/logs/alerts" 2>/dev/null; then
    chown wazuh:wazuh "${SHADOWTRACER_INSTALL_DIR}/logs/alerts"
    chmod 755 "${SHADOWTRACER_INSTALL_DIR}/logs/alerts"
    # The shipper runs on the host as a different uid than the wazuh user
    # inside this container, so alerts.json itself also needs to stay
    # world-readable for it - lab-only, a real deployment runs the shipper
    # as a sidecar sharing the manager's uid/mount instead of across a
    # host/container uid boundary.
    (while true; do chmod o+r "${SHADOWTRACER_INSTALL_DIR}/logs/alerts/alerts.json" 2>/dev/null || true; sleep 2; done) &
fi

# Phase 5C Step 0b follow-up: time sync is a real deployment requirement
# (the sequence-lateness window in shadowtracer_correlate/sequences.py
# assumes managers' clocks roughly agree) - chrony is installed and
# started on every manager. -x: this lab's containers share the HOST
# kernel's clock (no per-container clock namespace), so letting chronyd
# actually adjust it would slew the one clock every container AND the
# host itself uses, for a lab-only exercise - not something to do as a
# side effect of running this entrypoint. A real deployment runs each
# manager on its own OS/VM with its own independent clock; there, drop
# -x and let chronyd actually correct drift, which is the entire point
# of running it. Backgrounded, best-effort - a chronyd failure must
# never block the manager itself from starting.
mkdir -p /var/log/chrony
chronyd -x || true

"${SHADOWTRACER_INSTALL_DIR}/bin/shadowtracer-control" start

exec tail -F "${SHADOWTRACER_INSTALL_DIR}/logs/ossec.log" "${SHADOWTRACER_INSTALL_DIR}/logs/cluster.log" "${SHADOWTRACER_INSTALL_DIR}/logs/api.log" 2>/dev/null
