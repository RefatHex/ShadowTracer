from app import health as health_checks
from app.config import Settings


def _real_settings(lab_env, clickhouse_database):
    return Settings(
        jwt_secret="x" * 40,
        database_url="postgresql+psycopg2://unused:unused@127.0.0.1:5432/unused",
        clickhouse_host="127.0.0.1", clickhouse_port=8123,
        clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
        clickhouse_database=clickhouse_database,
        kafka_bootstrap_servers="127.0.0.1:9094",
        writer_consumer_group="shadowtracer-writer",
    )


def test_check_postgres_ok_against_real_db(db):
    ok, detail = health_checks.check_postgres(db)
    assert ok
    assert detail == "ok"


def test_check_clickhouse_ok_against_real_clickhouse(lab_env, test_clickhouse_db):
    ok, detail = health_checks.check_clickhouse(_real_settings(lab_env, test_clickhouse_db))
    assert ok


def test_check_kafka_ok_against_real_kafka(lab_env, test_clickhouse_db):
    ok, detail = health_checks.check_kafka(_real_settings(lab_env, test_clickhouse_db))
    assert ok


def test_readiness_report_all_healthy(db, lab_env, test_clickhouse_db):
    report = health_checks.readiness_report(db, _real_settings(lab_env, test_clickhouse_db))
    assert report["ready"] is True
    assert report["checks"]["postgres"]["ok"] is True
    assert report["checks"]["clickhouse"]["ok"] is True
    assert report["checks"]["kafka"]["ok"] is True


def test_check_clickhouse_reports_failure_for_wrong_port(lab_env, test_clickhouse_db):
    bad_settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(bad_settings, "clickhouse_port", 1)  # nothing listens there
    ok, detail = health_checks.check_clickhouse(bad_settings)
    assert not ok
    assert detail  # some real error message, not silently empty


def test_check_kafka_reports_failure_for_wrong_bootstrap(lab_env, test_clickhouse_db):
    bad_settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(bad_settings, "kafka_bootstrap_servers", "127.0.0.1:1")
    ok, detail = health_checks.check_kafka(bad_settings)
    assert not ok


def test_writer_consumer_lag_reports_zero_when_caught_up(lab_env, test_clickhouse_db):
    import time
    import uuid

    from confluent_kafka import Consumer, Producer
    from confluent_kafka.admin import AdminClient, NewTopic

    settings = _real_settings(lab_env, test_clickhouse_db)
    group_id = f"test-lag-{uuid.uuid4().hex[:8]}"
    topic = f"shadowtracer.test.lag.{uuid.uuid4().hex[:8]}"
    object.__setattr__(settings, "writer_consumer_group", group_id)

    admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers})
    admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)])
    time.sleep(1)
    try:
        producer = Producer({"bootstrap.servers": settings.kafka_bootstrap_servers})
        producer.produce(topic, value=b"x")
        producer.flush(10)

        consumer = Consumer({
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": group_id, "auto.offset.reset": "earliest", "enable.auto.commit": False,
        })
        consumer.subscribe([topic])
        msg = consumer.poll(10)
        assert msg is not None and msg.error() is None
        consumer.commit(msg)
        consumer.close()

        report = health_checks.writer_consumer_lag(settings)
        group = report[group_id]
        assert group["total_lag"] == 0
        assert group["oldest_unconsumed_age_seconds"] == 0
        assert group["alert"] is False
    finally:
        admin.delete_topics([topic])


def test_writer_consumer_lag_reports_age_when_behind(lab_env, test_clickhouse_db):
    """Offset lag alone doesn't say how close to falling off the topic's
    retention a stalled consumer is - this proves the age/fraction
    mechanics work (a few just-produced messages are seconds old, nowhere
    near 25% of a multi-day retention window, so alert stays False without
    needing to wait for real staleness)."""
    import time
    import uuid

    from confluent_kafka import Consumer, Producer
    from confluent_kafka.admin import AdminClient, NewTopic

    settings = _real_settings(lab_env, test_clickhouse_db)
    group_id = f"test-lag-{uuid.uuid4().hex[:8]}"
    topic = f"shadowtracer.test.lag.{uuid.uuid4().hex[:8]}"
    object.__setattr__(settings, "writer_consumer_group", group_id)

    admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers})
    admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)])
    time.sleep(1)
    try:
        producer = Producer({"bootstrap.servers": settings.kafka_bootstrap_servers})
        for _ in range(5):
            producer.produce(topic, value=b"x")
        producer.flush(10)

        consumer = Consumer({
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": group_id, "auto.offset.reset": "earliest", "enable.auto.commit": False,
        })
        consumer.subscribe([topic])
        for _ in range(2):  # consume+commit only 2 of 5 - leaves 3 behind
            msg = consumer.poll(10)
            assert msg is not None and msg.error() is None
            consumer.commit(msg)
        consumer.close()

        report = health_checks.writer_consumer_lag(settings)
        group = report[group_id]
        assert group["total_lag"] == 3
        assert group["oldest_unconsumed_age_seconds"] >= 0
        assert group["retention_seconds"] is not None
        assert group["fraction_of_retention"] >= 0
        assert group["alert"] is False
    finally:
        admin.delete_topics([topic])


def test_dead_letter_counts_per_tenant_zero_when_nothing_dead_lettered(lab_env, test_clickhouse_db):
    import uuid
    settings = _real_settings(lab_env, test_clickhouse_db)
    tenant = f"t-{uuid.uuid4().hex[:8]}"  # never written to, so guaranteed zero rows for it
    report = health_checks.dead_letter_counts_per_tenant(settings)
    assert "error" not in report
    assert tenant not in report["by_tenant"]


def _insert_dead_letter_rows(client, tenant, rows):
    """rows: list of (component, source_location, error, raw_event)."""
    import datetime
    import hashlib

    now = datetime.datetime.now(datetime.timezone.utc)
    client.insert(
        "dead_letter_events",
        [
            [tenant, component, source_location, error, raw_event, len(raw_event.encode()),
             hashlib.sha256(raw_event.encode()).hexdigest(), now]
            for component, source_location, error, raw_event in rows
        ],
        column_names=[
            "tenant_id", "component", "source_location", "error",
            "raw_event_preview", "raw_event_size", "raw_event_sha256", "failed_at",
        ],
    )


def test_dead_letter_counts_per_tenant_counts_real_rows(lab_env, test_clickhouse_db):
    import uuid

    import clickhouse_connect

    settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(settings, "dead_letter_alert_threshold", 1)  # low enough that 2 rows trips it
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123, username=lab_env["CLICKHOUSE_USER"],
        password=lab_env["CLICKHOUSE_PASSWORD"], database=test_clickhouse_db,
    )
    try:
        _insert_dead_letter_rows(client, tenant, [
            ("shipper", "alerts.json:10", "bad json", "{not json"),
            ("writer", "topic:0:5", "bad timestamp", "{}"),
        ])

        report = health_checks.dead_letter_counts_per_tenant(settings)
        assert "error" not in report
        assert report["threshold"] == 1
        assert report["alert"] is True
        assert report["by_tenant"][tenant]["total"] == 2
        assert report["by_tenant"][tenant]["over_threshold"] is True
        assert report["by_tenant"][tenant]["by_component"] == {"shipper": 1, "writer": 1}
    finally:
        client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant}'")
        client.close()


def test_dead_letter_counts_per_tenant_does_not_alert_below_threshold(lab_env, test_clickhouse_db):
    """Alerts on VOLUME, not just non-zero: a handful of dead-lettered
    events under the configured threshold must not raise the alert flag,
    even though the tenant's total is nonzero."""
    import uuid

    import clickhouse_connect

    settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(settings, "dead_letter_alert_threshold", 10)
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123, username=lab_env["CLICKHOUSE_USER"],
        password=lab_env["CLICKHOUSE_PASSWORD"], database=test_clickhouse_db,
    )
    try:
        _insert_dead_letter_rows(client, tenant, [
            ("shipper", "alerts.json:10", "bad json", "{not json"),
            ("writer", "topic:0:5", "bad timestamp", "{}"),
        ])

        report = health_checks.dead_letter_counts_per_tenant(settings)
        assert "error" not in report
        assert report["by_tenant"][tenant]["total"] == 2
        assert report["by_tenant"][tenant]["over_threshold"] is False
        assert report["alert"] is False
    finally:
        client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant}'")
        client.close()


def test_clickhouse_replica_health_all_healthy_against_real_cluster(lab_env, test_clickhouse_db):
    """Dead-letter-ClickHouse incident (2026-10-08): against the real,
    healthy lab cluster (both replicas), every replicated table on both
    hosts must come back is_readonly=0/is_session_expired=0."""
    settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(settings, "clickhouse_hosts", [("127.0.0.1", 8123), ("127.0.0.1", 8124)])

    report = health_checks.clickhouse_replica_health(settings)
    assert report["healthy"] is True
    assert report["unhealthy"] == []
    assert set(report["per_host"]) == {"127.0.0.1:8123", "127.0.0.1:8124"}
    for host_report in report["per_host"].values():
        assert host_report["ok"] is True
        tables = {t["table"] for t in host_report["tables"]}
        assert "dead_letter_events" in tables
        assert all(not t["is_readonly"] and not t["is_session_expired"] for t in host_report["tables"])


def test_clickhouse_replica_health_reports_unreachable_host(lab_env, test_clickhouse_db):
    """An unreachable replica (real connection failure, not a mock) must
    be reported, not silently dropped - this is exactly the kind of
    degraded-but-not-crashed state the real incident went undetected in."""
    settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(settings, "clickhouse_hosts", [("127.0.0.1", 1), ("127.0.0.1", 8123)])

    report = health_checks.clickhouse_replica_health(settings)
    assert report["healthy"] is False
    assert report["per_host"]["127.0.0.1:1"]["ok"] is False
    assert report["per_host"]["127.0.0.1:8123"]["ok"] is True
    assert any(u["host"] == "127.0.0.1:1" for u in report["unhealthy"])


def test_check_clickhouse_replicas_feeds_into_readiness_report(db, lab_env, test_clickhouse_db):
    """/health/ready must flip to not-ready when a configured replica is
    unreachable - not just when the single clickhouse_host/port check_clickhouse
    already covers happens to be the broken one."""
    settings = _real_settings(lab_env, test_clickhouse_db)
    object.__setattr__(settings, "clickhouse_hosts", [("127.0.0.1", 1), ("127.0.0.1", 8123)])

    report = health_checks.readiness_report(db, settings)
    assert report["ready"] is False
    assert report["checks"]["clickhouse_replicas"]["ok"] is False
    assert report["checks"]["clickhouse"]["ok"] is True  # the single-host check still points at the healthy one
