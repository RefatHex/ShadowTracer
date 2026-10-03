#!/usr/bin/env bash
# Explicitly provisions shadowtracer.events.raw with a fixed partition
# count, rather than relying on auto.create.topics.enable's implicit
# default (1) whenever the shipper/writer happen to produce/consume
# first - see DECISIONS.md's "Kafka partition count" entry for why 24,
# and why this is a create-once, not a resize: Kafka can't safely shrink
# partitions, and growing them later reshuffles which key (tenant_key +
# agent_id) lands on which partition, breaking per-agent ordering for
# every agent whose partition changes.
#
# Idempotent - does nothing if the topic already exists, intentionally:
# this script creates, it never resizes.
set -euo pipefail

TOPIC=shadowtracer.events.raw
PARTITIONS=24

if docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 --describe --topic "$TOPIC" >/dev/null 2>&1; then
    echo "$TOPIC already exists, leaving it alone"
else
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 --create --topic "$TOPIC" \
        --partitions "$PARTITIONS" --replication-factor 1
fi
