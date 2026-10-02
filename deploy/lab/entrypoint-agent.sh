#!/usr/bin/env bash
# Runtime configuration + enrollment for shadowtracer-lab agent images.
# Only ever touches the INSTALLED copy of ossec.conf inside the container,
# never the repo's tracked etc/ossec.conf.
set -uo pipefail

MANAGER_ENROLL_HOST="${MANAGER_ENROLL_HOST:?MANAGER_ENROLL_HOST is required}"
ENROLL_PASSWORD="${ENROLL_PASSWORD:?ENROLL_PASSWORD is required}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"
AGENT_MANAGER_DATA_HOST="${AGENT_MANAGER_DATA_HOST:-$MANAGER_ENROLL_HOST}"
AGENT_MANAGER_DATA_HOST_FALLBACK="${AGENT_MANAGER_DATA_HOST_FALLBACK:-}"

OSSEC_CONF=/var/ossec/etc/ossec.conf
CLIENT_KEYS=/var/ossec/etc/client.keys
FIM_TEST_DIR=/var/ossec/lab-fim-test

# Phase 3 follow-up 3: event data now goes through shadowtracer-lb
# (AGENT_MANAGER_DATA_HOST=shadowtracer-lb in docker-compose.yml), and
# enrollment below registers with a dynamic ("any") IP, not a static one -
# the static-IP-per-worker workaround from Phase 1/2 is removed now that
# the real bug (OS_IsValidIP()/isSingleHost(), see UPSTREAM.md) is fixed
# and re-verified through the LB.
sed -i "s|<address>.*</address>|<address>${AGENT_MANAGER_DATA_HOST}</address>|" "$OSSEC_CONF"

# --- one-time runtime config: a second <server> block, so this agent fails
# over to another worker if its primary goes down (Step 3 item 15) ---
if [ -n "$AGENT_MANAGER_DATA_HOST_FALLBACK" ] && ! grep -q "<address>${AGENT_MANAGER_DATA_HOST_FALLBACK}</address>" "$OSSEC_CONF"; then
    fallback_block="  <server><address>${AGENT_MANAGER_DATA_HOST_FALLBACK}</address><port>1514</port><protocol>tcp</protocol></server>"
    sed -i "0,/<\/server>/s|</server>|</server>\n${fallback_block}|" "$OSSEC_CONF"
fi

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

# Phase 3 follow-up 4: Rocky 9's stock rsyslog.conf ships
# imuxsock SysSock.Use="off", deferring local log collection entirely to
# systemd-journald ("local messages are retrieved through imjournal now" -
# its own comment) - there's no journald in this container, so neither
# path ever delivered anything to /var/log/secure (confirmed: no /dev/log
# socket, no journal). Re-enable the classic syslog socket so sshd's auth
# log actually reaches a file Wazuh can monitor. No-op on Debian/Ubuntu,
# which ships SysSock.Use="on" (or no such line) by default.
if [ -f /etc/rsyslog.conf ] && grep -q 'SysSock.Use="off"' /etc/rsyslog.conf; then
    sed -i 's/SysSock.Use="off"/SysSock.Use="on"/' /etc/rsyslog.conf
fi

service rsyslog start || rsyslogd || true
/usr/sbin/sshd

# --- enroll with the master if we don't already have keys ---
# Dynamic IP ("any") - see the note above sed-ing <address> for why this
# no longer needs -I <static-ip>.
if [ ! -s "$CLIENT_KEYS" ]; then
    for i in $(seq 1 60); do
        /var/ossec/bin/agent-auth -m "$MANAGER_ENROLL_HOST" -p 1515 -A "$AGENT_NAME" -P "$ENROLL_PASSWORD" -a && break
        echo "agent-auth: waiting for $MANAGER_ENROLL_HOST:1515 (attempt $i)"
        sleep 3
    done
fi

/var/ossec/bin/shadowtracer-control start

exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/active-responses.log 2>/dev/null
