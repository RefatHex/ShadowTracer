"""backfill_dead_letter_events.py: real lab Kafka + the isolated test
ClickHouse database (never the lab's real one - see conftest.py)."""

import json
import uuid

from confluent_kafka import Consumer, Producer

from backfill_dead_letter_events import backfill


def _publish_envelope(producer, topic, **overrides):
    envelope = {
        "tenant_key": "test", "component": "shipper", "source_location": "x:0",
        "error": "boom", "raw_event_preview": "{}", "raw_event_size": 2,
        "raw_event_sha256": "0" * 64, "failed_at": "2026-10-08T00:00:00+00:00",
    }
    envelope.update(overrides)
    producer.produce(topic, value=json.dumps(envelope).encode())
    producer.flush(5)
    return envelope


def _consumer(kafka_bootstrap, topic, group_id):
    consumer = Consumer({
        "bootstrap.servers": kafka_bootstrap,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([topic])
    return consumer


def test_backfill_inserts_rows_and_resuming_is_idempotent(kafka_topic, kafka_bootstrap, ch_client):
    producer = Producer({"bootstrap.servers": kafka_bootstrap})
    marker = uuid.uuid4().hex
    _publish_envelope(producer, kafka_topic, raw_event_sha256=marker.zfill(64)[:64])
    _publish_envelope(producer, kafka_topic)

    group_id = f"test-backfill-{uuid.uuid4().hex[:8]}"
    consumer = _consumer(kafka_bootstrap, kafka_topic, group_id)
    try:
        total = backfill(consumer, ch_client, kafka_topic)
    finally:
        consumer.close()
    assert total == 2

    rows = ch_client.query(
        "SELECT count() FROM dead_letter_events WHERE raw_event_sha256 = {sha:String}",
        parameters={"sha": marker.zfill(64)[:64]},
    ).result_rows
    assert rows[0][0] == 1

    # Re-running against the same consumer group (the realistic "did the
    # first run actually finish?" case) must not insert anything new -
    # the committed offsets mean there's nothing left to re-read.
    consumer2 = _consumer(kafka_bootstrap, kafka_topic, group_id)
    try:
        total2 = backfill(consumer2, ch_client, kafka_topic)
    finally:
        consumer2.close()
    assert total2 == 0

    rows_after = ch_client.query(
        "SELECT count() FROM dead_letter_events WHERE raw_event_sha256 = {sha:String}",
        parameters={"sha": marker.zfill(64)[:64]},
    ).result_rows
    assert rows_after[0][0] == 1, "re-running the backfill must not duplicate rows"


def test_backfill_skips_unparseable_envelope_without_blocking_the_rest(kafka_topic, kafka_bootstrap, ch_client):
    producer = Producer({"bootstrap.servers": kafka_bootstrap})
    producer.produce(kafka_topic, value=b"not json")
    marker = uuid.uuid4().hex
    _publish_envelope(producer, kafka_topic, raw_event_sha256=marker.zfill(64)[:64])
    producer.flush(5)

    group_id = f"test-backfill-{uuid.uuid4().hex[:8]}"
    consumer = _consumer(kafka_bootstrap, kafka_topic, group_id)
    try:
        total = backfill(consumer, ch_client, kafka_topic)
    finally:
        consumer.close()

    assert total == 1
    rows = ch_client.query(
        "SELECT count() FROM dead_letter_events WHERE raw_event_sha256 = {sha:String}",
        parameters={"sha": marker.zfill(64)[:64]},
    ).result_rows
    assert rows[0][0] == 1
