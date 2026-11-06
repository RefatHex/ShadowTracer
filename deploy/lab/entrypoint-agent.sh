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
# Rebrand Pass C prep: one setting for the install dir, default unchanged -
# see entrypoint-manager.sh's identical comment and docs/design/REBRAND_PASS_C.md.
SHADOWTRACER_INSTALL_DIR="${SHADOWTRACER_INSTALL_DIR:-/var/ossec}"

OSSEC_CONF="${SHADOWTRACER_INSTALL_DIR}/etc/ossec.conf"
CLIENT_KEYS="${SHADOWTRACER_INSTALL_DIR}/etc/client.keys"
FIM_TEST_DIR="${SHADOWTRACER_INSTALL_DIR}/lab-fim-test"

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

# Phase 7.0 (docs/ML_FOUNDATION.md): the test tenant's Linux lab agent watches, in real time,
# the paths that persistence/credential techniques and their legitimate look-alikes touch, so
# they are visible without auditd (no kernel audit in an unprivileged container). By agent
# name, so a restart applies it (a recreate would re-enroll the agent).
ML_FIM_PATHS="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/systemd/system /etc/init.d /etc/profile /etc/profile.d /etc/ld.so.preload /var/spool/cron /root /home"
if [ "$AGENT_NAME" = "agent-ubuntu-1" ] && ! grep -q "shadowtracer-ml-fim" "$OSSEC_CONF"; then
    mkdir -p /etc/sudoers.d /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/systemd/system /etc/profile.d /var/spool/cron/crontabs /root/.ssh
    touch /etc/ld.so.preload
    ml_dirs=$(echo $ML_FIM_PATHS | tr ' ' ',')
    ml_block="  <syscheck><!-- shadowtracer-ml-fim --><directories check_all=\"yes\" realtime=\"yes\" report_changes=\"no\">${ml_dirs}</directories></syscheck>"
    awk -v block="$ml_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
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

# A container restarted after an unclean stop (host power loss) keeps the
# previous run's /run/rsyslogd.pid; rsyslogd then refuses to start ("pidfile
# ... and pid N already exist", N now some other process) and no auth log is
# ever written. Nothing can be running yet at this point, so drop it.
rm -f /run/rsyslogd.pid /var/run/rsyslogd.pid
service rsyslog start || rsyslogd || true
/usr/sbin/sshd

# --- Phase 5C-1: auditd, with Wazuh's own "audit" log_format decoder
# watching its output. Real architectural limit, found running this
# directly, not assumed: the Linux audit subsystem is a single
# host-kernel-wide facility, not namespaced per container - every
# container sharing this host's kernel sees the SAME audit events
# (all syscalls on the host, not just this one container's), and only
# one auditd can hold the kernel's audit netlink socket at a time.
# Starting auditd here is real and does generate real events (needs
# CAP_AUDIT_CONTROL, granted in docker-compose.yml), but "per-agent
# auditd telemetry" does not mean per-container-isolated telemetry in
# this lab the way Wazuh's own alert pipeline is per-agent - documented
# in PHASE5C_SIGMA.md, not silently assumed away.
if command -v auditd >/dev/null 2>&1; then
    mkdir -p /var/log/audit
    augenrules --load || true
    auditd || true
fi
if [ -d /var/log/audit ] && ! grep -q "/var/log/audit/audit.log" "$OSSEC_CONF"; then
    audit_block="  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>"
    awk -v block="$audit_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
    mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
fi

# Phase 6.1b: outbound connection log (AGENT_NETLOG=1, docker-compose.yml sets it on
# agent-ubuntu-1 only, with cap NET_ADMIN), so destination-IP IOCs can match.
# iptables NFLOG on new outbound connections -> ulogd2 (userspace, this container's
# netns only - the kernel LOG target would write to the shared host kernel log) ->
# a file in kernel-LOG format. The "kernel: " prefix makes Wazuh's stock iptables-2
# decoder read it (srcip/dstip/ports; rule 4100), so no new decoder is needed.
# Licences: iptables GPL-2.0, ulogd2 GPL-2.0 (Debian copyright files).
if [ "${AGENT_NETLOG:-0}" = "1" ] && command -v ulogd >/dev/null 2>&1; then
    NETLOG=/var/log/shadowtracer-netlog.log
    iptables -C OUTPUT -m conntrack --ctstate NEW -j NFLOG --nflog-group 5 --nflog-prefix "kernel: ST-OUT" 2>/dev/null || \
        iptables -A OUTPUT -m conntrack --ctstate NEW -j NFLOG --nflog-group 5 --nflog-prefix "kernel: ST-OUT" || true
    U=/usr/lib/x86_64-linux-gnu/ulogd
    cat > /etc/ulogd-netlog.conf <<EOF
[global]
logfile="/var/log/ulogd.log"
plugin="$U/ulogd_inppkt_NFLOG.so"
plugin="$U/ulogd_raw2packet_BASE.so"
plugin="$U/ulogd_filter_IFINDEX.so"
plugin="$U/ulogd_filter_IP2STR.so"
plugin="$U/ulogd_filter_PRINTPKT.so"
plugin="$U/ulogd_output_LOGEMU.so"
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU
[log1]
group=5
[emu1]
file="$NETLOG"
sync=1
EOF
    pkill -x ulogd 2>/dev/null || true
    ulogd -d -c /etc/ulogd-netlog.conf || true
    touch "$NETLOG"
    if ! grep -q "$NETLOG" "$OSSEC_CONF"; then
        netlog_block="  <localfile><log_format>syslog</log_format><location>${NETLOG}</location></localfile>"
        awk -v block="$netlog_block" '/<\/ossec_config>/{print block} {print}' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
        mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
    fi
fi

# --- enroll with the master if we don't already have keys ---
# Dynamic IP ("any") - see the note above sed-ing <address> for why this
# no longer needs -I <static-ip>.
if [ ! -s "$CLIENT_KEYS" ]; then
    for i in $(seq 1 60); do
        "${SHADOWTRACER_INSTALL_DIR}/bin/agent-auth" -m "$MANAGER_ENROLL_HOST" -p 1515 -A "$AGENT_NAME" -P "$ENROLL_PASSWORD" -a && break
        echo "agent-auth: waiting for $MANAGER_ENROLL_HOST:1515 (attempt $i)"
        sleep 3
    done
fi

"${SHADOWTRACER_INSTALL_DIR}/bin/shadowtracer-control" start

exec tail -F "${SHADOWTRACER_INSTALL_DIR}/logs/ossec.log" "${SHADOWTRACER_INSTALL_DIR}/logs/active-responses.log" 2>/dev/null
