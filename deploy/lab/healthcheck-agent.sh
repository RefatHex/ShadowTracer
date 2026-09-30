#!/usr/bin/env bash
set -euo pipefail
[ -s /var/ossec/etc/client.keys ]
/var/ossec/bin/wazuh-control status | grep -q "wazuh-agentd.*is running"
