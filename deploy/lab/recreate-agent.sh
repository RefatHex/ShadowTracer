#!/usr/bin/env bash
# Recreates a lab agent container so it re-enrolls cleanly under its own name.
#
# A recreated agent container has no client.keys (no volume), so it enrolls
# again under the same name - and authd correctly refuses to hand an active
# (or recently active) agent's name to a new enrollment (Wazuh's default
# <force> policy, kept on purpose; see entrypoint-manager.sh). The supported
# way through is to remove the old registration on the master first, which
# is what this does, instead of weakening authd.
#
# Phase 6.1a: "the master" is the agent's own enrollment manager
# (MANAGER_ENROLL_HOST in docker-compose.yml) - shadowtracer-master for the
# main tenant, shadowtracer-worker-test for the test tenant, which is its own
# cluster. MASTER_OVERRIDE=<container> still overrides it.
#
# usage (from deploy/lab): ./recreate-agent.sh agent-ubuntu-1 [agent-ubuntu-2 ...]
set -euo pipefail
BIN=${SHADOWTRACER_INSTALL_DIR:-/var/ossec}/bin
enroll_manager() {  # <agent-service> -> container id of its MANAGER_ENROLL_HOST service
  local host
  host=$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"][sys.argv[1]]["environment"]["MANAGER_ENROLL_HOST"])' "$1")
  docker compose ps -q "$host"
}
[ $# -ge 1 ] || { echo "usage: $0 <agent-service> [...]" >&2; exit 2; }

for svc in "$@"; do
  cid=$(docker compose ps -q "$svc")
  [ -n "$cid" ] || { echo "no running container for service $svc" >&2; exit 1; }
  name=$(docker inspect "$cid" --format '{{.Config.Hostname}}')
  MASTER=${MASTER_OVERRIDE:-$(enroll_manager "$svc")}
  [ -n "$MASTER" ] || { echo "no running enrollment manager for $svc" >&2; exit 1; }
  # Same compose files the running project was created with (keeps any
  # gitignored override in effect for this service).
  files=$(docker inspect "$cid" --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}')
  compose=(docker compose); IFS=, read -ra fl <<<"$files"; for f in "${fl[@]}"; do compose+=(-f "$f"); done

  # Stop the old container first: if it is still retrying enrollment (a
  # recreate that was already refused), it would grab the name the moment
  # the old registration is removed.
  "${compose[@]}" stop "$svc" >/dev/null

  id=$(docker exec "$MASTER" "$BIN/agent_control" -l | awk -v n="$name" -F', ' '$2 == "Name: " n {sub(/.*ID: /, "", $1); print $1}')
  if [ -n "$id" ]; then
    echo "== $svc: removing old registration $id ($name) on $(docker inspect "$MASTER" --format '{{.Name}}')"
    docker exec "$MASTER" "$BIN/manage_agents" -r "$id" >/dev/null  # -r is non-interactive (sets OSSEC_ACTION_CONFIRMED)
  else
    echo "== $svc: no existing registration for $name"
  fi

  echo "== $svc: recreating container"
  "${compose[@]}" up -d --force-recreate --no-deps "$svc"

  echo "== $svc: waiting for $name to enroll and become Active"
  for _ in $(seq 1 60); do
    line=$(docker exec "$MASTER" "$BIN/agent_control" -l | grep "Name: $name," || true)
    if grep -q "Active" <<<"$line"; then echo "$line"; continue 2; fi
    sleep 3
  done
  echo "$svc did not become Active within 180s:" >&2
  docker exec "$MASTER" "$BIN/agent_control" -l >&2
  exit 1
done
