#!/usr/bin/env bash
set -euo pipefail
[ -s /var/ossec/etc/client.keys ]
# Capture first, then grep the variable - piping directly into `grep -q`
# lets grep exit as soon as it matches, SIGPIPE-ing shadowtracer-control status
# while it's still writing. Under pipefail that non-zero (141) exit code
# fails the whole pipeline even though the match succeeded.
STATUS="$(/var/ossec/bin/shadowtracer-control status)"
echo "$STATUS" | grep -q "wazuh-agentd.*is running"
