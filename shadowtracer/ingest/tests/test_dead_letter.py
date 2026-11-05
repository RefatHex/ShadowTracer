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
import pytest
from confluent_kafka import Consumer, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from shadowtracer_ingest.dead_letter import send_batch_to_dead_letter, send_to_dead_letter
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.metrics import Metrics
from shadowtracer_ingest.topics import alerts_topic_for_tenant, dead_letter_topic_for_tenant

# Phase 5.6 Item 1: several tests below use the literal tenant_key
# "test" (predates per-tenant topics) - provisioned once, idempotently,
# rather than renaming every call site to a fresh per-test tenant for a
# module that was never about tenant isolation in the first place.
_SHARED_TEST_TENANT = "test"


@pytest.fixture(scope="module", autouse=True)
def _provision_shared_test_tenant_topics(kafka_bootstrap):
    import time
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    futures = admin.create_topics([
        NewTopic(alerts_topic_for_tenant(_SHARED_TEST_TENANT), num_partitions=1, replication_factor=1),
        NewTopic(dead_letter_topic_for_tenant(_SHARED_TEST_TENANT), num_partitions=1, replication_factor=1),
    ])
    for future in futures.values():
        try:
            future.result()
        except Exception as exc:  # noqa: BLE001 - idempotent across repeated test runs: already existing is fine, anything else isn't
            if "already exists" not in str(exc):
                raise
    time.sleep(1)


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
        **kafka_client_config_from_env(),
    })
    consumer.subscribe([dead_letter_topic_for_tenant(_SHARED_TEST_TENANT)])
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
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
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
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})

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
    source_location = f"shadowtracer.t.test.alerts:3:{uuid.uuid4().hex[:8]}"

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


def _non_creating_producer(kafka_bootstrap):
    # The lab's writer/correlator principals can't create topics; this test
    # runs as admin, so turn auto-creation off to get the same situation.
    return Producer({"bootstrap.servers": kafka_bootstrap, "allow.auto.create.topics": False,
                     **kafka_client_config_from_env()})


def test_offboarded_tenant_dead_letter_lands_in_clickhouse_instead_of_retrying_forever(kafka_bootstrap, ch_client):
    """Tenant offboarding: the tenant's dead-letter topic is gone, so the Kafka
    publish can never succeed. Before the fix every caller retried it forever
    and stalled its partitions; now the ClickHouse row is the durable record."""
    import time
    tenant_key = f"test-off-{uuid.uuid4().hex[:8]}"
    producer = _non_creating_producer(kafka_bootstrap)
    metrics = Metrics()
    try:
        started = time.monotonic()
        send_to_dead_letter(
            kafka_producer=producer, ch_client=ch_client, tenant_key=tenant_key,
            component="writer", source_location=f"shadowtracer.t.{tenant_key}.alerts:0:7",
            error="unknown_tenant", raw_event="{}", metrics=metrics,
        )
        assert time.monotonic() - started < 30
        rows = ch_client.query(
            "SELECT error FROM dead_letter_events WHERE tenant_id = {t:String}", parameters={"t": tenant_key},
        ).result_rows
        assert len(rows) == 1 and "tenant offboarded" in rows[0][0], rows
        assert metrics.snapshot().get("dead_letter_topic_missing") == 1

        # The timed-out publish must not linger in the producer and fail the
        # next dead letter for a tenant whose topic does exist.
        send_to_dead_letter(
            kafka_producer=producer, ch_client=None, tenant_key=_SHARED_TEST_TENANT,
            component="writer", source_location="x", error="x", raw_event="{}",
        )
    finally:
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant_key}'")


def test_offboarded_tenant_without_clickhouse_still_raises(kafka_bootstrap):
    """No ClickHouse sink means no durable record at all - keep failing."""
    with pytest.raises(Exception):
        send_to_dead_letter(
            kafka_producer=_non_creating_producer(kafka_bootstrap), ch_client=None,
            tenant_key=f"test-off-{uuid.uuid4().hex[:8]}", component="writer",
            source_location="x", error="x", raw_event="{}",
        )


def test_unreachable_broker_is_never_mistaken_for_an_offboarded_tenant(ch_client):
    """The fallback needs positive proof the topic is gone; a broker that
    can't answer metadata at all stays a transient failure."""
    with pytest.raises(Exception):
        send_to_dead_letter(
            kafka_producer=Producer({"bootstrap.servers": "127.0.0.1:1", "message.timeout.ms": 2000}),
            ch_client=ch_client, tenant_key="test", component="writer",
            source_location="x", error="x", raw_event="{}",
        )


def test_a_burst_of_dead_letters_is_one_flush_and_one_insert(kafka_bootstrap, ch_client):
    """A burst of malformed input (alerts.json lines split by a second writer,
    THROUGHPUT_BASELINE.md §13) cost one producer flush plus one ClickHouse
    round trip PER EVENT and held the shipper to ~25 lines/s. A batch must be
    one flush and one insert, with every event still recorded in both sinks.
    Counting wrappers around the real producer and client, not mocks."""
    flushes, inserts = [], []

    class CountingProducer(Producer):
        def flush(self, *args):
            flushes.append(1)
            return super().flush(*args)

    class CountingClickHouse:
        def insert(self, table, rows, **kwargs):
            inserts.append(len(rows))
            return ch_client.insert(table, rows, **kwargs)

    marker = f"burst-{uuid.uuid4().hex}"
    failures = [(f"burst:{i}", marker, f"not json {i}") for i in range(300)]
    try:
        send_batch_to_dead_letter(
            kafka_producer=CountingProducer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()}),
            ch_client=CountingClickHouse(), tenant_key=_SHARED_TEST_TENANT, component="shipper",
            failures=failures,
        )
        assert flushes == [1] and inserts == [300], (flushes, inserts)
        stored = ch_client.query(
            "SELECT uniqExact(source_location) FROM dead_letter_events WHERE error = {m:String}", parameters={"m": marker},
        ).result_rows[0][0]
        assert stored == 300
        assert _drain_dead_letter_topic(kafka_bootstrap, marker) is not None
    finally:
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE error = '{marker}'")
