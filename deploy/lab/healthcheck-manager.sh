#!/usr/bin/env bash
# wazuh-maild/agentlessd/integratord/csyslogd are disabled by default and
# legitimately report "not running" - only check the daemons this lab
# actually needs, not every daemon shadowtracer-control knows about.
set -euo pipefail
SHADOWTRACER_INSTALL_DIR="${SHADOWTRACER_INSTALL_DIR:-/var/ossec}"
STATUS=$("${SHADOWTRACER_INSTALL_DIR}/bin/shadowtracer-control" status) || true
for d in wazuh-execd wazuh-analysisd wazuh-syscheckd wazuh-remoted \
         wazuh-logcollector wazuh-monitord wazuh-modulesd wazuh-db \
         wazuh-authd wazuh-apid wazuh-clusterd; do
    echo "$STATUS" | grep -q "^${d} is running" || exit 1
done
