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

# --- one-time runtime config: enable the osquery wodle and give osqueryd
# an actual query schedule - the wodle ships <disabled>yes</disabled> and
# /etc/osquery/osquery.conf never existed, so osqueryd ran with nothing to
# collect and Wazuh's own osquery module exited immediately either way ---
if grep -q '<wodle name="osquery">' "$OSSEC_CONF"; then
    sed -i '/<wodle name="osquery">/,/<\/wodle>/ s|<disabled>yes</disabled>|<disabled>no</disabled>|' "$OSSEC_CONF"
fi
if [ ! -f /etc/osquery/osquery.conf ]; then
    mkdir -p /etc/osquery
    cat > /etc/osquery/osquery.conf <<'EOF'
{
  "schedule": {
    "system_info": { "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;", "interval": 60 },
    "listening_ports": { "query": "SELECT pid, port, protocol FROM listening_ports;", "interval": 60 }
  }
}
EOF
fi

# --- system services the capability tests need ---
# osqueryd itself is NOT started here: the osquery wodle above runs with
# <run_daemon>yes</run_daemon>, meaning Wazuh spawns and owns its own
# osqueryd process. A second, independently-started osqueryd collides with
# it over osquery's own sqlite lock file and osqueryd exits (code 78).
mkdir -p /run/sshd
service rsyslog start || rsyslogd || true
/usr/sbin/sshd

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
