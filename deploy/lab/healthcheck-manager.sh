#!/usr/bin/env bash
set -euo pipefail
/var/ossec/bin/wazuh-control status | grep -q "is running" && \
! /var/ossec/bin/wazuh-control status | grep -q "not running"
