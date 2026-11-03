"""replay_unknown_tenant_dead_letters.py: real lab Kafka + the isolated
test Postgres/ClickHouse databases (never the lab's real ones - see
conftest.py). Drives the real writer.run() for the "does the replayed
event actually land" proof, same spirit as test_writer.py's own tests."""

import json
import threading
import time
import uuid

import pytest
from confluent_kafka import Consumer, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from conftest import TEST_CLICKHOUSE_DB, delete_topics_and_wait, insert_tenant
from replay_unknown_tenant_dead_letters import known_tenants, replay
from shadowtracer_ingest import writer
from shadowtracer_ingest.dead_letter import send_to_dead_letter
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.metrics import Metrics
from shadowtracer_ingest.topics import DEAD_LETTER_TOPIC_PATTERN, alerts_topic_for_tenant, dead_letter_topic_for_tenant


@pytest.fixture(autouse=True)
def _default_lab_tenant(pg_db):
    insert_tenant(pg_db, "lab")


def _provision_tenant_topics(kafka_bootstrap, tenant_key):
    """Phase 5.6 Item 1: these tests exercise a tenant that's
    DELIBERATELY not yet in `tenants` - but its topic PAIR must still
    exist (topics are provisioned explicitly, never auto-created, same
    "explicit, not implicit" stance as the lab's own
    create-kafka-topics.sh) before anything can produce to or replay
    from it."""
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    admin.create_topics([
        NewTopic(alerts_topic_for_tenant(tenant_key), num_partitions=1, replication_factor=1),
        NewTopic(dead_letter_topic_for_tenant(tenant_key), num_partitions=1, replication_factor=1),
    ])
    time.sleep(1)
    return admin


def _dead_letter_unknown_tenant_event(kafka_bootstrap, tenant_key, alert_id, source_location):
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    raw_event = json.dumps({
        "timestamp": "2026-01-01T12:00:00.000+0000", "id": alert_id,
        "rule": {"id": "5710", "level": 5, "description": "test", "groups": ["sshd"]},
        "agent": {"id": "agent-1", "name": "agent-1", "ip": "10.0.0.1"},
        "manager": {"name": "wazuh-worker1"}, "cluster": {"node": "worker1"},
        "data": {"srcip": "9.9.9.9"}, "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log", "full_log": "test",
    })
    send_to_dead_letter(
        kafka_producer=producer, ch_client=None, tenant_key=tenant_key,
        component="writer", source_location=source_location,
        error="unknown_tenant", raw_event=raw_event,
    )
    return raw_event


def _count_alert_ids(ch_client, alert_ids):
    placeholders = ",".join(f"'{a}'" for a in alert_ids)
    return ch_client.query(f"SELECT count() FROM events FINAL WHERE alert_id IN ({placeholders})").result_rows[0][0]


def test_replay_lands_the_event_once_the_tenant_exists(
    kafka_bootstrap, ch_client, lab_env, pg_db, database_url,
):
    """The exact gap tenants.py's own docstring documents: an event
    dead-lettered as unknown_tenant, for a tenant that GENUINELY didn't
    exist at the time, must be recoverable once it does - replayed back
    onto its own real alerts topic and picked up by a real writer.run(),
    landing in ClickHouse exactly as if it had arrived fresh.

    Phase 5.6 Item 1: replay() no longer takes topic arguments - it
    pattern-subscribes across every tenant's dead-letter topic and
    replays onto each one's own alerts topic, derived from the
    dead-letter topic each envelope actually came from."""
    marker = uuid.uuid4().hex[:8]
    tenant_key = f"test-replay-{marker}"
    alert_id = f"{marker}.replayed"
    source_location = f"shadowtracer.t.{tenant_key}.alerts:0:{marker}"
    _provision_tenant_topics(kafka_bootstrap, tenant_key)

    # Dead-lettered while the tenant genuinely doesn't exist yet.
    _dead_letter_unknown_tenant_event(kafka_bootstrap, tenant_key, alert_id, source_location)

    group_id = f"test-replay-unknown-tenant-{marker}"
    consumer = Consumer({
        "bootstrap.servers": kafka_bootstrap, "group.id": group_id,
        "enable.auto.commit": False, "auto.offset.reset": "earliest",
        **kafka_client_config_from_env(),
    })
    consumer.subscribe([DEAD_LETTER_TOPIC_PATTERN])
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    # Tenant still unknown: nothing to replay yet, and it must not be
    # silently committed past - a second run must still see it.
    stats = replay(consumer, producer, known_tenants(database_url))
    consumer.close()  # must fully leave the group before a second consumer in the SAME group joins, or the rebalance races
    assert stats["replayed"] == 0
    assert stats["still_unknown"] >= 1

    # Now the tenant genuinely exists.
    insert_tenant(pg_db, tenant_key)

    consumer2 = Consumer({
        "bootstrap.servers": kafka_bootstrap, "group.id": group_id,
        "enable.auto.commit": False, "auto.offset.reset": "earliest",
        **kafka_client_config_from_env(),
    })
    consumer2.subscribe([DEAD_LETTER_TOPIC_PATTERN])
    try:
        stats2 = replay(consumer2, producer, known_tenants(database_url))
    finally:
        consumer2.close()
    assert stats2["replayed"] == 1

    # A real writer.run(), proving the replayed event lands exactly like
    # a fresh one would - not calling normalize_alert/insert_batch directly.
    metrics = Metrics()
    stop_flag = threading.Event()
    started_flag = threading.Event()
    thread = threading.Thread(
        target=writer.run,
        kwargs=dict(
            bootstrap_servers=kafka_bootstrap,
            group_id=f"test-writer-{marker}",
            clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
            clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
            clickhouse_database=TEST_CLICKHOUSE_DB, database_url=database_url,
            metrics=metrics, stop_flag=stop_flag, started_flag=started_flag,
            kafka_client_config=kafka_client_config_from_env(),
        ),
        daemon=True,
    )
    thread.start()
    assert started_flag.wait(timeout=10)
    try:
        # Phase 5.6 Item 1: 40s, not 20s - see test_writer.py's
        # test_writer_is_actually_running_and_draining_not_just_callable
        # for the margin this accounts for (a brand-new consumer group's
        # pattern-subscription group-join under a busy shared test cluster).
        deadline = time.monotonic() + 40
        count = 0
        while time.monotonic() < deadline:
            count = _count_alert_ids(ch_client, [alert_id])
            if count == 1:
                break
            time.sleep(0.5)
        assert count == 1, "the replayed event must land in ClickHouse exactly like a fresh one would"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id = '{alert_id}'")
        delete_topics_and_wait(
            AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()}),
            [alerts_topic_for_tenant(tenant_key), dead_letter_topic_for_tenant(tenant_key)],
        )


def test_replay_skips_truncated_events_as_unrecoverable(kafka_bootstrap, pg_db, database_url):
    """An event whose raw_event exceeded the 4KB preview cap can't be
    replayed with full fidelity - replaying the truncated preview alone
    would re-ingest corrupted (truncated-JSON) data, so it must be
    skipped and counted, never silently "replayed" as garbage."""
    marker = uuid.uuid4().hex[:8]
    tenant_key = f"test-truncated-{marker}"
    insert_tenant(pg_db, tenant_key)
    _provision_tenant_topics(kafka_bootstrap, tenant_key)

    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    huge_raw_event = json.dumps({"id": f"{marker}.huge", "full_log": "x" * 100_000})
    send_to_dead_letter(
        kafka_producer=producer, ch_client=None, tenant_key=tenant_key,
        component="writer", source_location=f"shadowtracer.t.{tenant_key}.alerts:0:{marker}",
        error="unknown_tenant", raw_event=huge_raw_event,
    )

    group_id = f"test-replay-truncated-{marker}"
    consumer = Consumer({
        "bootstrap.servers": kafka_bootstrap, "group.id": group_id,
        "enable.auto.commit": False, "auto.offset.reset": "earliest",
        **kafka_client_config_from_env(),
    })
    consumer.subscribe([DEAD_LETTER_TOPIC_PATTERN])
    try:
        stats = replay(consumer, producer, known_tenants(database_url))
        assert stats["truncated"] >= 1
        assert stats["replayed"] == 0
    finally:
        consumer.close()
        delete_topics_and_wait(
            AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()}),
            [alerts_topic_for_tenant(tenant_key), dead_letter_topic_for_tenant(tenant_key)],
        )
