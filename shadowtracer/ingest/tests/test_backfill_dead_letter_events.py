"""backfill_dead_letter_events.py: real lab Kafka + the isolated test
ClickHouse database (never the lab's real one - see conftest.py)."""

import datetime
import json
import uuid

from confluent_kafka import Consumer, Producer

from backfill_dead_letter_events import backfill
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.topics import dead_letter_topic_for_tenant


def _publish_envelope(producer, topic, **overrides):
    # source_location defaults to something unique per call, not a fixed
    # "x:0" - dead_letter_events is a ReplicatedReplacingMergeTree keyed on
    # (tenant_id, component, source_location) now (Phase 5C Step 0), so two
    # genuinely different messages sharing a hardcoded source_location
    # would collide as "the same identity" and one could replace the
    # other - exactly the backfill idempotency this test wants to prove,
    # just not an accident between two UNRELATED messages that happen to
    # share a hardcoded location.
    envelope = {
        "tenant_key": "test", "component": "shipper", "source_location": f"x:{uuid.uuid4().hex[:8]}",
        "error": "boom", "raw_event_preview": "{}", "raw_event_size": 2,
        # recent, not a hardcoded past date: dead_letter_events has TTL failed_at + 30 days, so a
        # fixed old date time-bombs this test (it broke the day 2026-10-08 + 30d came round).
        "raw_event_sha256": "0" * 64, "failed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
        **kafka_client_config_from_env(),
    })
    consumer.subscribe([topic])
    return consumer


def test_backfill_inserts_rows_and_resuming_is_idempotent(kafka_tenant_key, kafka_topic, kafka_bootstrap, ch_client):
    dlt_topic = dead_letter_topic_for_tenant(kafka_tenant_key)
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    marker = uuid.uuid4().hex
    _publish_envelope(producer, dlt_topic, tenant_key=kafka_tenant_key, raw_event_sha256=marker.zfill(64)[:64])
    _publish_envelope(producer, dlt_topic, tenant_key=kafka_tenant_key)

    group_id = f"test-backfill-{uuid.uuid4().hex[:8]}"
    consumer = _consumer(kafka_bootstrap, dlt_topic, group_id)
    try:
        total = backfill(consumer, ch_client)
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
    consumer2 = _consumer(kafka_bootstrap, dlt_topic, group_id)
    try:
        total2 = backfill(consumer2, ch_client)
    finally:
        consumer2.close()
    assert total2 == 0

    rows_after = ch_client.query(
        "SELECT count() FROM dead_letter_events WHERE raw_event_sha256 = {sha:String}",
        parameters={"sha": marker.zfill(64)[:64]},
    ).result_rows
    assert rows_after[0][0] == 1, "re-running the backfill must not duplicate rows"


def test_backfill_skips_unparseable_envelope_without_blocking_the_rest(kafka_tenant_key, kafka_topic, kafka_bootstrap, ch_client):
    dlt_topic = dead_letter_topic_for_tenant(kafka_tenant_key)
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    producer.produce(dlt_topic, value=b"not json")
    marker = uuid.uuid4().hex
    _publish_envelope(producer, dlt_topic, tenant_key=kafka_tenant_key, raw_event_sha256=marker.zfill(64)[:64])
    producer.flush(5)

    group_id = f"test-backfill-{uuid.uuid4().hex[:8]}"
    consumer = _consumer(kafka_bootstrap, dlt_topic, group_id)
    try:
        total = backfill(consumer, ch_client)
    finally:
        consumer.close()

    assert total == 1
    rows = ch_client.query(
        "SELECT count() FROM dead_letter_events WHERE raw_event_sha256 = {sha:String}",
        parameters={"sha": marker.zfill(64)[:64]},
    ).result_rows
    assert rows[0][0] == 1
