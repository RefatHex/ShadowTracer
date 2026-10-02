from app import health as health_checks
from app.config import Settings


def _real_settings(lab_env):
    return Settings(
        jwt_secret="x" * 40,
        database_url="postgresql+psycopg2://unused:unused@127.0.0.1:5432/unused",
        clickhouse_host="127.0.0.1", clickhouse_port=8123,
        clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
        clickhouse_database="shadowtracer",
        kafka_bootstrap_servers="127.0.0.1:9094",
        writer_consumer_group="shadowtracer-writer",
    )


def test_check_postgres_ok_against_real_db(db):
    ok, detail = health_checks.check_postgres(db)
    assert ok
    assert detail == "ok"


def test_check_clickhouse_ok_against_real_clickhouse(lab_env):
    ok, detail = health_checks.check_clickhouse(_real_settings(lab_env))
    assert ok


def test_check_kafka_ok_against_real_kafka(lab_env):
    ok, detail = health_checks.check_kafka(_real_settings(lab_env))
    assert ok


def test_readiness_report_all_healthy(db, lab_env):
    report = health_checks.readiness_report(db, _real_settings(lab_env))
    assert report["ready"] is True
    assert report["checks"]["postgres"]["ok"] is True
    assert report["checks"]["clickhouse"]["ok"] is True
    assert report["checks"]["kafka"]["ok"] is True


def test_check_clickhouse_reports_failure_for_wrong_port(lab_env):
    bad_settings = _real_settings(lab_env)
    object.__setattr__(bad_settings, "clickhouse_port", 1)  # nothing listens there
    ok, detail = health_checks.check_clickhouse(bad_settings)
    assert not ok
    assert detail  # some real error message, not silently empty


def test_check_kafka_reports_failure_for_wrong_bootstrap(lab_env):
    bad_settings = _real_settings(lab_env)
    object.__setattr__(bad_settings, "kafka_bootstrap_servers", "127.0.0.1:1")
    ok, detail = health_checks.check_kafka(bad_settings)
    assert not ok
