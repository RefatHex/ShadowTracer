#!/usr/bin/env bash
# Runtime configuration + enrollment for shadowtracer-lab agent images.
# Only ever touches the INSTALLED copy of ossec.conf inside the container,
# never the repo's tracked etc/ossec.conf.
set -uo pipefail

MANAGER_ENROLL_HOST="${MANAGER_ENROLL_HOST:?MANAGER_ENROLL_HOST is required}"
ENROLL_PASSWORD="${ENROLL_PASSWORD:?ENROLL_PASSWORD is required}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"
AGENT_MANAGER_DATA_HOST="${AGENT_MANAGER_DATA_HOST:-$MANAGER_ENROLL_HOST}"
AGENT_IP="$(hostname -i | awk '{print $1}')"

OSSEC_CONF=/var/ossec/etc/ossec.conf
CLIENT_KEYS=/var/ossec/etc/client.keys
FIM_TEST_DIR=/var/ossec/lab-fim-test

# Connect for event data directly to this agent's assigned worker, not the
# baked-in USER_AGENT_SERVER_NAME - see docker-compose.yml's note on why
# agent traffic can't go through the shared-IP load balancer in this build.
sed -i "s|<address>.*</address>|<address>${AGENT_MANAGER_DATA_HOST}</address>|" "$OSSEC_CONF"

# --- one-time runtime config: extra FIM-watched directory for step 3.6 ---
if ! grep -q "$FIM_TEST_DIR" "$OSSEC_CONF"; then
    mkdir -p "$FIM_TEST_DIR"
    fim_block="  <syscheck><directories check_all=\"yes\" realtime=\"yes\">${FIM_TEST_DIR}</directories></syscheck>"
    awk -v block="$fim_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
    mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
fi

# --- one-time runtime config: monitor the sshd auth log (not in the
# default localfile list) so the brute-force/active-response tests fire ---
AUTH_LOG=/var/log/auth.log
[ -f /etc/debian_version ] || AUTH_LOG=/var/log/secure
if ! grep -q "$AUTH_LOG" "$OSSEC_CONF"; then
    # rsyslog runs as syslog:adm (mode 0640) after dropping root - pre-create
    # the file with root:root/644 (plain touch) and rsyslog can never write
    # to it, so nothing ever lands here. Match rsyslog's own file ownership.
    touch "$AUTH_LOG"
    chown syslog:adm "$AUTH_LOG" 2>/dev/null || true
    chmod 640 "$AUTH_LOG"
    auth_block="  <localfile><log_format>syslog</log_format><location>${AUTH_LOG}</location></localfile>"
    awk -v block="$auth_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
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
        /var/ossec/bin/agent-auth -m "$MANAGER_ENROLL_HOST" -p 1515 -A "$AGENT_NAME" -P "$ENROLL_PASSWORD" -I "$AGENT_IP" -a && break
        echo "agent-auth: waiting for $MANAGER_ENROLL_HOST:1515 (attempt $i)"
        sleep 3
    done
fi

/var/ossec/bin/wazuh-control start

exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/active-responses.log 2>/dev/null
