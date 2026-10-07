#!/usr/bin/env bash
# Explicitly provisions shadowtracer.events.raw and
# shadowtracer.events.dead-letter, rather than relying on
# auto.create.topics.enable's implicit defaults (1 partition, and
# whatever retention.ms the broker happens to default to) whenever a
# producer/consumer happens to touch the topic first.
#
# Partition count is create-once, never resized later - see
# DECISIONS.md's "Kafka partition count" entry for why 24 for events.raw
# (and why growing it later would reshuffle key-to-partition mapping and
# break per-agent ordering). events.dead-letter gets far fewer
# partitions (6) since its volume is expected to be a small fraction of
# the main event stream's - no replay-ordering guarantee depends on it
# the way events.raw's does, so under-provisioning it isn't the same
# one-way door.
#
# retention.ms, unlike partition count, IS safe to change later (it's a
# dynamic topic config, not a structural property) - this script always
# re-applies it, even for a topic that already exists, so a change here
# actually takes effect on every re-run. See DECISIONS.md's "Kafka
# retention" entry for why 7 days and why explicit.
set -euo pipefail

RETENTION_MS=604800000  # 7 days

create_topic_if_missing() {
    local topic="$1" partitions="$2"
    if docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 --describe --topic "$topic" >/dev/null 2>&1; then
        echo "$topic already exists, leaving its partition count alone"
    else
        docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
            --bootstrap-server localhost:9092 --create --topic "$topic" \
            --partitions "$partitions" --replication-factor 1
    fi
}

set_retention() {
    local topic="$1"
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-configs.sh \
        --bootstrap-server localhost:9092 --alter --entity-type topics --entity-name "$topic" \
        --add-config "retention.ms=$RETENTION_MS"
}

create_topic_if_missing shadowtracer.events.raw 24
set_retention shadowtracer.events.raw

create_topic_if_missing shadowtracer.events.dead-letter 6
set_retention shadowtracer.events.dead-letter
