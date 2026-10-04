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


def test_dead_letter_counts_per_tenant_zero_when_nothing_dead_lettered(lab_env, test_clickhouse_db):
    import uuid
    settings = _real_settings(lab_env, test_clickhouse_db)
    tenant = f"t-{uuid.uuid4().hex[:8]}"  # never written to, so guaranteed zero rows for it
    report = health_checks.dead_letter_counts_per_tenant(settings)
    assert "error" not in report
    assert tenant not in report["by_tenant"]


def test_dead_letter_counts_per_tenant_counts_real_rows(lab_env, test_clickhouse_db):
    import datetime
    import uuid

    import clickhouse_connect

    settings = _real_settings(lab_env, test_clickhouse_db)
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123, username=lab_env["CLICKHOUSE_USER"],
        password=lab_env["CLICKHOUSE_PASSWORD"], database=test_clickhouse_db,
    )
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        client.insert(
            "dead_letter_events",
            [
                [tenant, "shipper", "alerts.json:10", "bad json", "{not json", now],
                [tenant, "writer", "topic:0:5", "bad timestamp", "{}", now],
            ],
            column_names=["tenant_id", "component", "source_location", "error", "raw_event", "failed_at"],
        )

        report = health_checks.dead_letter_counts_per_tenant(settings)
        assert "error" not in report
        assert report["alert"] is True
        assert report["by_tenant"][tenant]["total"] == 2
        assert report["by_tenant"][tenant]["by_component"] == {"shipper": 1, "writer": 1}
    finally:
        client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant}'")
        client.close()
