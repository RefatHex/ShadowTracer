"""Fixtures. Per the project's guardrails, these hit real PostgreSQL
(deploy/lab/docker-compose.yml) over its published host port - never
SQLite, never a mock - but only the isolated shadowtracer_test database,
created and wiped fresh every session, never the lab's real one. See
_refuse_if_pointed_at_lab_database, and
shadowtracer/console/backend/tests/conftest.py /
shadowtracer/ingest/tests/conftest.py for the same pattern used there.
"""

import os
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import clickhouse_connect
import psycopg2
import pytest
from confluent_kafka.admin import AdminClient, NewTopic
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "deploy", "lab", ".env")
INGEST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ingest")
_CLICKHOUSE_SCHEMA_PATH = os.path.join(INGEST_DIR, "schema", "events_schema.sql")

TEST_POSTGRES_DB = "shadowtracer_test"
# Session-unique, not a fixed "shadowtracer_test" - found the hard way
# (2026-10-08, see MEMORY/project_test_suite_db_race.md): a shared fixed
# name let this suite's session-start DROP+recreate race the ingest
# suite's own identical fixture when both ran concurrently against the
# same real cluster. Generated once at conftest import time (= once per
# pytest session, same as the Keeper path prefix below), dropped again at
# session end so it doesn't orphan a database per run.
TEST_CLICKHOUSE_DB = f"shadowtracer_test_{uuid.uuid4().hex[:8]}"
LAB_CLICKHOUSE_DB = "shadowtracer"


def _load_env() -> dict:
    env = {}
    with open(ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k] = v
    return env


def _refuse_if_pointed_at_lab_database(lab_postgres_db: str) -> None:
    """Hard guard, checked before any test runs (and statically by
    check-project.sh): if the test database name ever resolves to the
    lab's real one, refuse outright instead of touching production
    data."""
    if TEST_POSTGRES_DB == lab_postgres_db:
        pytest.exit(
            f"refusing to run: test Postgres database {TEST_POSTGRES_DB!r} "
            f"is the lab's real database - tests must never touch lab data",
            returncode=1,
        )
    if TEST_CLICKHOUSE_DB == LAB_CLICKHOUSE_DB:
        pytest.exit(
            f"refusing to run: test ClickHouse database {TEST_CLICKHOUSE_DB!r} "
            f"is the lab's real database {LAB_CLICKHOUSE_DB!r} - tests must "
            f"never touch lab data",
            returncode=1,
        )


@pytest.fixture(scope="session")
def lab_env():
    return _load_env()


@pytest.fixture(scope="session", autouse=True)
def _isolated_postgres_test_database(lab_env):
    """Drops and recreates shadowtracer_test fresh at the start of every
    test session, then runs the real Alembic migrations against it - the
    same database shadowtracer/console/backend's tests use, independently
    ensured here so this suite can also run standalone."""
    _refuse_if_pointed_at_lab_database(lab_postgres_db=lab_env["POSTGRES_DB"])

    admin_conn = psycopg2.connect(
        host="127.0.0.1", port=5432,
        user=lab_env["POSTGRES_USER"], password=lab_env["POSTGRES_PASSWORD"],
        dbname=lab_env["POSTGRES_DB"],
    )
    admin_conn.autocommit = True
    try:
        with admin_conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS {TEST_POSTGRES_DB} WITH (FORCE)")
            cur.execute(f"CREATE DATABASE {TEST_POSTGRES_DB}")
    finally:
        admin_conn.close()

    migration_env = {
        **os.environ,
        "POSTGRES_USER": lab_env["POSTGRES_USER"],
        "POSTGRES_PASSWORD": lab_env["POSTGRES_PASSWORD"],
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": TEST_POSTGRES_DB,
        "APP_DB_PASSWORD": lab_env["APP_DB_PASSWORD"],
    }
    subprocess.run(
        [os.path.join(INGEST_DIR, ".venv", "bin", "alembic"), "upgrade", "head"],
        cwd=INGEST_DIR, env=migration_env, check=True, capture_output=True, text=True,
    )


@pytest.fixture(scope="session")
def database_url(lab_env):
    return (
        f"postgresql+psycopg2://{lab_env['POSTGRES_USER']}:{lab_env['POSTGRES_PASSWORD']}"
        f"@127.0.0.1:5432/{TEST_POSTGRES_DB}"
    )


@pytest.fixture(scope="session")
def engine(database_url, _isolated_postgres_test_database):
    return create_engine(database_url, pool_pre_ping=True)


@pytest.fixture
def db(engine):
    """A real session against the isolated test database, truncated back
    to empty after every test."""
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.rollback()
    session.execute(text(
        "TRUNCATE TABLE fingerprint_verdicts, incident_alerts, incidents, "
        "fingerprints, agent_role_tags, tenant_alert_settings, sequence_progress, "
        "campaign_incidents, campaigns "
        "RESTART IDENTITY CASCADE"
    ))
    session.commit()
    session.close()


@pytest.fixture(scope="session", autouse=True)
def _isolated_clickhouse_test_database(lab_env):
    """Creates this session's own TEST_CLICKHOUSE_DB (already
    session-unique - see its definition above), applying the one schema
    source (schema/events_schema.sql) under a fresh Keeper path prefix -
    see that file's header, and shadowtracer/ingest/tests/conftest.py's
    identical fixture, for why - and drops it again at session end, since
    nothing else will ever reuse this exact random name."""
    _refuse_if_pointed_at_lab_database(lab_postgres_db=lab_env["POSTGRES_DB"])

    admin_client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
    )
    keeper_prefix = f"test-{uuid.uuid4().hex[:8]}/"
    with open(_CLICKHOUSE_SCHEMA_PATH) as f:
        schema_sql = f.read().replace("__DATABASE__", TEST_CLICKHOUSE_DB).replace("__KEEPER_PREFIX__", keeper_prefix)
    uncommented = re.sub(r"--.*$", "", schema_sql, flags=re.MULTILINE)
    for statement in uncommented.split(";"):
        statement = statement.strip()
        if statement:
            admin_client.command(statement)
    yield
    admin_client.command(f"DROP DATABASE IF EXISTS {TEST_CLICKHOUSE_DB} ON CLUSTER lab_cluster")
    admin_client.close()


@pytest.fixture
def ch_client(lab_env, _isolated_clickhouse_test_database):
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database=TEST_CLICKHOUSE_DB,
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def kafka_bootstrap():
    return "127.0.0.1:9094"


@pytest.fixture
def kafka_topic(kafka_bootstrap):
    name = f"shadowtracer.test.{uuid.uuid4().hex[:8]}"
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap})
    admin.create_topics([NewTopic(name, num_partitions=1, replication_factor=1)])
    time.sleep(1)  # topic metadata propagation
    yield name
    admin.delete_topics([name])
