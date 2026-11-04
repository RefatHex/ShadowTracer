#!/usr/bin/env bash
# Throughput-baseline tooling: skips the TEST tenant's alerts-topic backlog for
# the writer and correlator groups (offsets -> latest), so one stage's leftover
# backlog doesn't contaminate the next measurement. Test tenant topic ONLY -
# no other tenant's partitions are named in the reset. Skipped messages never
# reach ClickHouse/Postgres. Run from deploy/lab.
set -euo pipefail
TEST_TENANT_KEY="${TEST_TENANT_KEY:-6da85d3ba8d9b0974ea6d3e712575eca}"
set -a; source .env; set +a
export KAFKA_SECURITY_PROTOCOL=SASL_SSL KAFKA_SASL_USERNAME=admin KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD" KAFKA_SSL_CA_LOCATION="$PWD/kafka-certs/ca.crt"
SERVICES=(shadowtracer-lab-writer-1-1 shadowtracer-lab-writer-2-1 shadowtracer-lab-correlate-1-1 shadowtracer-lab-correlate-2-1)

docker stop "${SERVICES[@]}" >/dev/null
trap 'docker start "${SERVICES[@]}" >/dev/null' EXIT

../../shadowtracer/correlate/.venv/bin/python3 - "$TEST_TENANT_KEY" <<'EOF'
import sys, time
sys.path.insert(0, "../../shadowtracer/ingest")
from confluent_kafka import Consumer, TopicPartition, ConsumerGroupTopicPartitions
from confluent_kafka.admin import AdminClient
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.topics import alerts_topic_for_tenant

cfg, b = kafka_client_config_from_env(), "127.0.0.1:9094"
topic = alerts_topic_for_tenant(sys.argv[1])
admin = AdminClient({"bootstrap.servers": b, **cfg})
wm = Consumer({"bootstrap.servers": b, "group.id": "skip-test-backlog", "enable.auto.commit": False, **cfg})
parts = sorted(admin.list_topics(topic, timeout=10).topics[topic].partitions)
for group in ("shadowtracer-writer", "shadowtracer-correlate"):
    for _ in range(30):  # stopped members leave the group within session.timeout
        if not admin.describe_consumer_groups([group])[group].result(timeout=10).members:
            break
        time.sleep(2)
    tps = [TopicPartition(topic, p, wm.get_watermark_offsets(TopicPartition(topic, p), timeout=5, cached=False)[1]) for p in parts]
    before = admin.list_consumer_group_offsets([ConsumerGroupTopicPartitions(group, [TopicPartition(topic, p) for p in parts])])[group].result(timeout=10)
    admin.alter_consumer_group_offsets([ConsumerGroupTopicPartitions(group, tps)])[group].result(timeout=10)
    for old, new in zip(before.topic_partitions, tps):
        print(f"{group} {topic}[{new.partition}] {old.offset} -> {new.offset} (skipped {new.offset - max(old.offset, 0)})")
EOF
