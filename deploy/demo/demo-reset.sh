#!/usr/bin/env bash
# Phase 7.8 demo: clean the TEST tenant for a fresh recording, check every
# container is healthy, and print a status table. Starts a NEW run-id (writes
# deploy/demo/.demo_run_id) that the warmup/scenario steps then tag their data
# with. Non-destructive to real history: it removes demo-tagged events and
# closes the TEST tenant's open incidents so the Live view starts calm; it never
# touches another tenant.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-common.sh"

banner 0 "DEMO RESET  ·  clean TEST tenant + health check"

PREV="$(run_id)"
say "previous run-id: ${PREV}"

# 1) remove demo-tagged events (brute usernames 'demo-*', eicar paths, load-demo-* agents)
say "deleting demo-tagged ClickHouse events for the TEST tenant…"
chq "ALTER TABLE shadowtracer.events DELETE WHERE tenant_id='$TENANT' AND (raw_event LIKE '%demo-%' OR raw_event LIKE '%load-demo-%')" >/dev/null || true
ok "delete mutation submitted (asynchronous)"

# 2) close open incidents for the TEST tenant so the Live view starts empty, and
#    drop the synthetic demo agents' incidents entirely (load-demo-*, replay-*).
say "closing open TEST-tenant incidents + removing synthetic demo-agent incidents…"
pgq "UPDATE incidents SET state='closed', closed_at=now() WHERE tenant_key='$TENANT' AND state='open'" >/dev/null || true
pgq "DELETE FROM incident_ti    WHERE tenant_key='$TENANT' AND incident_id IN (SELECT id FROM incidents WHERE tenant_key='$TENANT' AND (agent_id LIKE 'load-demo-%' OR agent_id LIKE 'replay-%'))" >/dev/null || true
pgq "DELETE FROM incident_alerts WHERE tenant_key='$TENANT' AND incident_id IN (SELECT id FROM incidents WHERE tenant_key='$TENANT' AND (agent_id LIKE 'load-demo-%' OR agent_id LIKE 'replay-%'))" >/dev/null || true
pgq "DELETE FROM incidents       WHERE tenant_key='$TENANT' AND (agent_id LIKE 'load-demo-%' OR agent_id LIKE 'replay-%')" >/dev/null || true
ok "incidents reset"

# 3) health check every lab container
banner 1 "CONTAINER HEALTH"
printf "   %-42s %-10s %s\n" "CONTAINER" "STATE" "HEALTH"
printf "   %-42s %-10s %s\n" "----------------------------------------" "--------" "------"
unhealthy=0
while read -r name; do
  [ -z "$name" ] && continue
  state="$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo "?")"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' "$name" 2>/dev/null || echo "?")"
  mark=""
  if [ "$state" != "running" ]; then mark=" <--"; unhealthy=$((unhealthy+1)); fi
  if [ "$health" = "unhealthy" ] || [ "$health" = "starting" ]; then mark=" <--"; unhealthy=$((unhealthy+1)); fi
  printf "   %-42s %-10s %s%s\n" "$name" "$state" "$health" "$mark"
done < <(docker ps -a --filter "name=shadowtracer-lab-" --format '{{.Names}}' | sort)

echo
if [ "$unhealthy" -eq 0 ]; then ok "all containers running / healthy"; else warn "$unhealthy container(s) not ready - see <-- above"; fi

# 4) new run-id for this take
NEW="$(new_run_id)"
banner 9 "READY  ·  new run-id ${NEW}"
say "next: deploy/demo/demo-warmup.sh   then   deploy/demo/demo-scenario.sh <step>"
[ "$unhealthy" -eq 0 ] || exit 1
