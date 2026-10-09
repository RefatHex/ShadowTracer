"""Dead-letter-ClickHouse incident (2026-10-08) hardening. Real infra
only - a "broken" producer means pointed at a real unreachable broker; a
"broken" ClickHouse client means a real, successful connection to a
database that genuinely lacks dead_letter_events (get_client() itself
validates the connection at construction time, so a connection-level
failure would raise before send_to_dead_letter is ever entered rather than
inside its own try/except). Never a mock object standing in for
clickhouse_connect/confluent_kafka."""

import uuid

import clickhouse_connect
from confluent_kafka import Consumer, Producer

from shadowtracer_ingest.dead_letter import send_to_dead_letter
from shadowtracer_ingest.metrics import Metrics


def _broken_ch_client(lab_env):
    # get_client() itself eagerly validates the connection (it queries
    # SELECT version(), timezone() at construction time) - found the hard
    # way, pointing this at an unreachable port fails before
    # send_to_dead_letter is ever entered, not inside its try/except.
    # Pointed at "default" instead: a real, successful connection to the
    # real lab ClickHouse, to a database that genuinely has no
    # dead_letter_events table - the insert() call itself fails, which is
    # the exact code path being tested, and closer to the real incident's
    # own shape (a healthy connection, a broken table) than a bare
    # connection failure would be.
    return clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database="default",
    )


def _drain_dead_letter_topic(kafka_bootstrap, expected_alert_id, timeout=15):
    import time
    consumer = Consumer({
        "bootstrap.servers": kafka_bootstrap,
        "group.id": f"test-dlt-drain-{uuid.uuid4().hex[:8]}",
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe(["shadowtracer.events.dead-letter"])
    deadline = time.monotonic() + timeout
    found = None
    while time.monotonic() < deadline:
        msg = consumer.poll(1.0)
        if msg is not None and msg.error() is None and expected_alert_id in msg.value().decode():
            found = msg.value().decode()
            break
    consumer.close()
    return found


def test_clickhouse_insert_failure_does_not_raise_increments_metric_kafka_copy_still_lands(kafka_bootstrap, lab_env):
    """ClickHouse insert fails (real connection, real missing-table error) -
    must not raise, must count dead_letter_ch_failures, and the Kafka
    dead-letter topic copy must still land (it's published first, before
    the ClickHouse attempt - see dead_letter.py's own ordering)."""
    marker = uuid.uuid4().hex
    producer = Producer({"bootstrap.servers": kafka_bootstrap})
    metrics = Metrics()

    send_to_dead_letter(
        kafka_producer=producer, ch_client=_broken_ch_client(lab_env), tenant_key="test",
        component="test", source_location="x", error="x",
        raw_event=f'{{"id": "{marker}"}}', metrics=metrics,
    )

    assert metrics.snapshot().get("dead_letter_ch_failures") == 1
    found = _drain_dead_letter_topic(kafka_bootstrap, marker)
    assert found is not None, "the Kafka dead-letter topic copy must still land even when ClickHouse fails"


def test_kafka_publish_failure_raises_not_silently_succeeds():
    """A broker-unreachable kind of delivery failure must raise, not
    silently return - confirmed empirically that confluent_kafka's
    produce()/flush() alone do NOT detect this (flush() returns 0 'still
    pending' even when the message actually timed out undelivered; the
    failure only ever surfaces via the delivery callback). This is the
    exact gap the fix closes - this test would have passed even with the
    bug (no exception raised), which is why the Kafka-side check is a
    positive assertion on the raise, not just "it doesn't crash"."""
    unreachable_producer = Producer({"bootstrap.servers": "127.0.0.1:1", "message.timeout.ms": 2000})
    try:
        send_to_dead_letter(
            kafka_producer=unreachable_producer, ch_client=None, tenant_key="test",
            component="test", source_location="x", error="x", raw_event="{}",
        )
        assert False, "expected send_to_dead_letter to raise when the Kafka publish never durably succeeds"
    except Exception as exc:
        assert "did not durably succeed" in str(exc)


def test_dead_letter_preview_truncation_still_applies_when_clickhouse_is_broken(kafka_bootstrap, lab_env):
    """Regression guard: the 4 KB preview truncation (so an oversized
    raw_event doesn't blow up the envelope this module itself produces)
    must still apply on the Kafka side even when the ClickHouse side is
    broken - the two code paths share the same preview/size/sha256
    computation, this just confirms the ClickHouse failure doesn't skip
    or corrupt it for the Kafka copy."""
    marker = uuid.uuid4().hex
    huge_raw_event = f'{{"id": "{marker}", "full_log": "' + ("x" * 100_000) + '"}'
    producer = Producer({"bootstrap.servers": kafka_bootstrap})

    send_to_dead_letter(
        kafka_producer=producer, ch_client=_broken_ch_client(lab_env), tenant_key="test",
        component="test", source_location="x", error="x", raw_event=huge_raw_event,
    )

    found = _drain_dead_letter_topic(kafka_bootstrap, marker)
    assert found is not None
    assert len(found.encode()) < 10_000, "the envelope must still be capped, not the full 100KB raw_event"


def test_replaying_the_same_dead_letter_does_not_duplicate_the_row(kafka_bootstrap, lab_env, ch_client):
    """Phase 5C Step 0: dead_letter_events is a ReplicatedReplacingMergeTree
    keyed on (tenant_id, component, source_location) - see
    events_schema.sql's own comment. Calling send_to_dead_letter twice for
    the SAME message (a real replay: the same component dead-lettering the
    same topic:partition:offset again) must not leave two rows for it.
    uniqExact(source_location) is correct immediately (the same fix
    health.py's dead_letter_counts_per_tenant needed); a plain count()
    only becomes correct after a merge, forced here with OPTIMIZE ... FINAL
    so the test doesn't depend on background merge timing."""
    tenant_key = f"test-{uuid.uuid4().hex[:8]}"
    source_location = f"shadowtracer.events.raw:3:{uuid.uuid4().hex[:8]}"

    for _ in range(2):
        send_to_dead_letter(
            kafka_producer=None, ch_client=ch_client, tenant_key=tenant_key,
            component="writer", source_location=source_location,
            error="KeyError: 'timestamp'", raw_event="{}",
        )

    try:
        immediate = ch_client.query(
            "SELECT uniqExact(source_location) FROM dead_letter_events "
            "WHERE tenant_id = {t:String} AND component = 'writer'",
            parameters={"t": tenant_key},
        ).result_rows[0][0]
        assert immediate == 1, "uniqExact must be correct immediately, before any merge"

        ch_client.command("OPTIMIZE TABLE dead_letter_events FINAL")
        after_merge = ch_client.query(
            "SELECT count() FROM dead_letter_events WHERE tenant_id = {t:String} AND component = 'writer'",
            parameters={"t": tenant_key},
        ).result_rows[0][0]
        assert after_merge == 1, "a forced merge must collapse the replayed duplicate down to one row"
    finally:
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant_key}'")
