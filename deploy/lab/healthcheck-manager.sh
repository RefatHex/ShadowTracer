#!/usr/bin/env bash
# wazuh-maild/agentlessd/integratord/csyslogd are disabled by default and
# legitimately report "not running" - only check the daemons this lab
# actually needs, not every daemon wazuh-control knows about.
set -euo pipefail
STATUS=$(/var/ossec/bin/wazuh-control status) || true
for d in wazuh-execd wazuh-analysisd wazuh-syscheckd wazuh-remoted \
         wazuh-logcollector wazuh-monitord wazuh-modulesd wazuh-db \
         wazuh-authd wazuh-apid wazuh-clusterd; do
    echo "$STATUS" | grep -q "^${d} is running" || exit 1
done
