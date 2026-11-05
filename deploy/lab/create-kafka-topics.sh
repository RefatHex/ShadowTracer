#!/usr/bin/env bash
# Phase 5.6 Item 1: provisions a per-tenant topic PAIR
# (shadowtracer.t.<tenant_key>.alerts, .dead-letter) rather than the old
# single shared shadowtracer.events.raw/.dead-letter - see
# docs/design/KAFKA_AUTH.md for why (option a: a Kafka ACL is
# resource-scoped, not content-scoped, so only a per-tenant TOPIC lets
# the broker itself refuse a cross-tenant produce attempt).
#
# Partition count: 3 per topic, same number for alerts and dead-letter.
# Justification (replaces the old 24/6 split, which sized for ALL
# tenants sharing one topic): per tenant, headroom for the lab's 2
# writer + 2 correlate replicas each needs at least 2 partitions to
# split work at all; 3 (not 2) leaves the same "N+1 for an odd-replica
# split" headroom DECISIONS.md's old 24-partition entry used ("3
# happened to allow a 2/1 split by accident"). Growing this later is
# still a one-way door (resizing reshuffles agent_id-hash ordering), but
# per-tenant the blast radius of under-provisioning ONE tenant is just
# that tenant, not the whole system - and a new tenant gets a brand new
# topic at provisioning time anyway, so its count can be chosen fresh
# against that tenant's real expected load rather than guessed for
# every future tenant combined, the way the old global 24 had to.
#
# Usage:
#   ./create-kafka-topics.sh                  # provisions TENANT_KEY and TEST_TENANT_KEY from .env
#   ./create-kafka-topics.sh <tenant_key> [partitions]   # provisions one arbitrary tenant (e.g. a VERIFY script's ephemeral tenant)
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

PARTITIONS=3
# The test tenant carries the load tests (docs/THROUGHPUT_BASELINE.md 13):
# 12 alerts partitions - divides evenly over 2, 3, 4 or 6 consumer replicas,
# and >= 2x any replica count the lab runs; see docs/design/THROUGHPUT_FIXES.md
# "partitions per tenant by size" (> 2,000/s tier).
TEST_TENANT_PARTITIONS=${TEST_TENANT_PARTITIONS:-12}
RETENTION_MS=604800000  # 7 days, unchanged from before - see DECISIONS.md's "Kafka retention" entry

# Phase 5.6 Item 1: admin operations (topic create/describe) run as the
# admin SCRAM principal once SASL is enabled - auto-detected from
# whether kafka-certs/admin-client.properties exists on the HOST (same
# file generate-kafka-certs.sh writes and the kafka service mounts into
# the container at the fixed path below), not an env var every caller
# would otherwise have to remember to set. Before the two-phase
# bootstrap (generate-kafka-certs.sh hasn't run yet, or SASL isn't
# enabled on the broker yet), this file doesn't exist, so these calls
# correctly run unauthenticated instead - same as before this item.
CLIENT_CONFIG_ARGS=()
if [ -f "kafka-certs/admin-client.properties" ]; then
    CLIENT_CONFIG_ARGS=(--command-config /etc/kafka/certs/admin-client.properties)
fi

create_topic_if_missing() {
    local topic="$1" partitions="$2"
    if docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 "${CLIENT_CONFIG_ARGS[@]}" --describe --topic "$topic" >/dev/null 2>&1; then
        local current
        current=$(docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
            --bootstrap-server localhost:9092 "${CLIENT_CONFIG_ARGS[@]}" --describe --topic "$topic" \
            | grep -o 'PartitionCount: *[0-9]*' | grep -o '[0-9]*$')
        if [ "$current" -lt "$partitions" ]; then
            # Increase only (Kafka can't decrease). Re-maps keys once: per-key
            # ordering is not guaranteed across this change.
            docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
                --bootstrap-server localhost:9092 "${CLIENT_CONFIG_ARGS[@]}" --alter --topic "$topic" --partitions "$partitions"
            echo "$topic: partitions $current -> $partitions"
        else
            echo "$topic already exists with $current partitions, leaving it alone"
        fi
    else
        docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
            --bootstrap-server localhost:9092 "${CLIENT_CONFIG_ARGS[@]}" --create --topic "$topic" \
            --partitions "$partitions" --replication-factor 1
    fi
}

set_retention() {
    local topic="$1"
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-configs.sh \
        --bootstrap-server localhost:9092 "${CLIENT_CONFIG_ARGS[@]}" --alter --entity-type topics --entity-name "$topic" \
        --add-config "retention.ms=$RETENTION_MS"
}

provision_tenant() {
    local tenant_key="$1" alerts_partitions="${2:-$PARTITIONS}"
    local alerts_topic="shadowtracer.t.${tenant_key}.alerts"
    local dead_letter_topic="shadowtracer.t.${tenant_key}.dead-letter"
    create_topic_if_missing "$alerts_topic" "$alerts_partitions"
    set_retention "$alerts_topic"
    create_topic_if_missing "$dead_letter_topic" "$PARTITIONS"
    set_retention "$dead_letter_topic"
}

if [ "$#" -ge 1 ]; then
    provision_tenant "$1" "${2:-$PARTITIONS}"
else
    provision_tenant "${TENANT_KEY:?set TENANT_KEY in deploy/lab/.env}"
    provision_tenant "${TEST_TENANT_KEY:?set TEST_TENANT_KEY in deploy/lab/.env}" "$TEST_TENANT_PARTITIONS"
fi
