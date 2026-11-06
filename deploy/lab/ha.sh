#!/usr/bin/env bash
# Switch the lab between the default compose profile and "ha" (second ClickHouse replica,
# worker1/worker2 and their shippers; DEV_SETUP.md "Compose profiles").
#
#   ./ha.sh up     before a chaos/failover run
#   ./ha.sh down   after it
#
# Memory (backlog R7, owner decision 2026-11-06): while "ha" runs, ti-sync and ti-matcher
# are stopped - the "ha" limits total 14,160 MiB, 13,648 without them, under the
# 13,824 MiB cap (stopping ti-sync alone leaves 13,904). Both are off the hot path:
# ti-matcher resumes from its committed offsets with no missed matches (6.1c), ti-sync
# simply syncs later and VirusTotal lookups wait in their queue.
set -euo pipefail
cd "$(dirname "$0")"
HA=(--env-file .env --env-file ha.env)
case "${1:-}" in
    up)
        docker compose stop ti-sync ti-matcher
        # every service except the two paused ones, so the cap is never crossed even briefly
        mapfile -t svcs < <(docker compose "${HA[@]}" config --services | grep -vx -e ti-sync -e ti-matcher)
        docker compose "${HA[@]}" up -d "${svcs[@]}"
        ./create-clickhouse-schema.sh
        echo "ha profile up; ti-sync and ti-matcher stopped until ./ha.sh down"
        ;;
    down)
        docker compose --profile ha rm -sf shadowtracer-worker1 shadowtracer-worker2 shipper-worker1 shipper-worker2 ch-clickhouse-2
        docker compose up -d          # default env: ch1 one-replica cluster, console lists; starts ti-sync, ti-matcher
        echo "default profile up (volumes of the ha services kept)"
        ;;
    *)
        echo "usage: $0 up|down" >&2; exit 2 ;;
esac
