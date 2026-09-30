#!/usr/bin/env bash
# Runtime configuration + enrollment for shadowtracer-lab agent images.
# Only ever touches the INSTALLED copy of ossec.conf inside the container,
# never the repo's tracked etc/ossec.conf.
set -uo pipefail

MANAGER_ENROLL_HOST="${MANAGER_ENROLL_HOST:?MANAGER_ENROLL_HOST is required}"
ENROLL_PASSWORD="${ENROLL_PASSWORD:?ENROLL_PASSWORD is required}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"

OSSEC_CONF=/var/ossec/etc/ossec.conf
CLIENT_KEYS=/var/ossec/etc/client.keys
FIM_TEST_DIR=/var/ossec/lab-fim-test

# --- one-time runtime config: extra FIM-watched directory for step 3.6 ---
if ! grep -q "$FIM_TEST_DIR" "$OSSEC_CONF"; then
    mkdir -p "$FIM_TEST_DIR"
    fim_block="  <syscheck><directories check_all=\"yes\" realtime=\"yes\">${FIM_TEST_DIR}</directories></syscheck>"
    awk -v block="$fim_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
    mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
fi

# --- system services the capability tests need ---
mkdir -p /run/sshd
service rsyslog start || rsyslogd || true
/usr/sbin/sshd
command -v osqueryd >/dev/null 2>&1 && (osqueryd --config_path=/etc/osquery/osquery.conf --pidfile=/var/run/osqueryd.pid --daemonize --disable_watchdog || true)

# --- enroll with the master if we don't already have keys ---
if [ ! -s "$CLIENT_KEYS" ]; then
    for i in $(seq 1 60); do
        /var/ossec/bin/agent-auth -m "$MANAGER_ENROLL_HOST" -p 1515 -A "$AGENT_NAME" -P "$ENROLL_PASSWORD" -a && break
        echo "agent-auth: waiting for $MANAGER_ENROLL_HOST:1515 (attempt $i)"
        sleep 3
    done
fi

/var/ossec/bin/wazuh-control start

exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/active-responses.log 2>/dev/null
