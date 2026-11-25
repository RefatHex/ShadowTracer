#!/usr/bin/env bash
# Phase 9 A5: provision a least-privilege Wazuh API user for SOAR active-response dispatch.
#
# Creates (idempotently) a user `soar`, a policy allowing ONLY active-response:command on the given
# agents, a role, and binds them. SOAR then authenticates as this user instead of wazuh-wui, so a
# leaked SOAR credential cannot manage agents, read logs, or change config — only fire AR commands.
#
# Wazuh RBAC resources for active-response are agent:id:<id> (there is no per-script resource), so the
# script-name restriction to shadowtracer-* is enforced on OUR side (SOAR only ever dispatches
# !shadowtracer-* scripts). Scope here is the agent ids passed in (the test-tenant agents).
#
# Usage:  SOAR_WAZUH_API_PASSWORD=... ./provision-soar-api-user.sh [agent_id ...]
# Admin credentials come from WAZUH_API_USER/WAZUH_API_PASSWORD (default wazuh-wui); the new user's
# password from SOAR_WAZUH_API_PASSWORD (env only, never hard-coded). Default agents: 001 002 003.
set -euo pipefail

API="${WAZUH_API:-https://127.0.0.1:55000}"
ADMIN_USER="${WAZUH_API_USER:-wazuh-wui}"
ADMIN_PW="${WAZUH_API_PASSWORD:-wazuh-wui}"
SOAR_USER="${SOAR_WAZUH_API_USER:-soar}"
SOAR_PW="${SOAR_WAZUH_API_PASSWORD:?set SOAR_WAZUH_API_PASSWORD in the environment}"
AGENTS=("${@:-001 002 003}")

curlk() { curl -sk "$@"; }
TOKEN=$(curlk -u "$ADMIN_USER:$ADMIN_PW" -X POST "$API/security/user/authenticate?raw=true")
auth=(-H "Authorization: Bearer $TOKEN")
jqget() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

# resources list: agent:id:<id> for each agent
RES=$(python3 - "$@" <<'PY'
import sys, json
agents = sys.argv[1:] or ["001","002","003"]
print(json.dumps([{"agent:id:%s" % a: "allow"} for a in agents]))
PY
)

echo "== user =="
curlk "${auth[@]}" -H 'Content-Type: application/json' -X POST "$API/security/users" \
  -d "{\"username\":\"$SOAR_USER\",\"password\":\"$SOAR_PW\"}" | jqget "d.get('message') or d.get('error')" || true

echo "== policy (active-response:command only) =="
POLICY_BODY=$(python3 - "$@" <<'PY'
import sys, json
agents = sys.argv[1:] or ["001","002","003"]
print(json.dumps({
  "name": "soar_active_response_only",
  "policy": {"actions": ["active-response:command"],
             "resources": ["agent:id:%s" % a for a in agents],
             "effect": "allow"}}))
PY
)
curlk "${auth[@]}" -H 'Content-Type: application/json' -X POST "$API/security/policies" \
  -d "$POLICY_BODY" | jqget "d.get('message') or d.get('error')" || true

echo "== role =="
curlk "${auth[@]}" -H 'Content-Type: application/json' -X POST "$API/security/roles" \
  -d '{"name":"soar_responder"}' | jqget "d.get('message') or d.get('error')" || true

# resolve ids and bind role<-policy, user<-role
UID_=$(curlk "${auth[@]}" "$API/security/users?search=$SOAR_USER" | jqget "d['data']['affected_items'][0]['id']")
RID=$(curlk "${auth[@]}" "$API/security/roles?search=soar_responder" | jqget "d['data']['affected_items'][0]['id']")
PID=$(curlk "${auth[@]}" "$API/security/policies?search=soar_active_response_only" | jqget "d['data']['affected_items'][0]['id']")

echo "== bind policy->role, role->user =="
curlk "${auth[@]}" -X POST "$API/security/roles/$RID/policies?policy_ids=$PID" | jqget "d.get('message') or d.get('error')" || true
curlk "${auth[@]}" -X POST "$API/security/users/$UID_/roles?role_ids=$RID" | jqget "d.get('message') or d.get('error')" || true

echo "Done. SOAR user id=$UID_ role=$RID policy=$PID. Set SOAR_WAZUH_API_USER=$SOAR_USER and"
echo "SOAR_WAZUH_API_PASSWORD in deploy/lab/.env so the SOAR worker uses it."
