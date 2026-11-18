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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))

import clickhouse_connect
import psycopg2
import pytest
from confluent_kafka.admin import AdminClient, NewTopic
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.topics import alerts_topic_for_tenant, dead_letter_topic_for_tenant


def delete_topics_and_wait(admin: AdminClient, topics: list[str], timeout: float = 10.0) -> None:
    """confluent_kafka's delete_topics() returns immediately with a
    future per topic - not waiting on them risks the broker never
    actually receiving the request before the admin client (and its
    underlying rd_kafka handle) gets torn down. Confirmed the hard way
    this session: topics deleted this way were still listed by the
    broker, with their full backlog intact, long after the test that
    "deleted" them had already returned - the real mechanism behind
    hours of orphaned-topic accumulation. Swallows per-topic errors
    (already-gone is fine; this is cleanup, not an assertion). Same
    helper as shadowtracer/ingest/tests/conftest.py's own."""
    futures = admin.delete_topics(topics)
    for future in futures.values():
        try:
            future.result(timeout=timeout)
        except Exception:
            pass


ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "deploy", "lab", ".env")
INGEST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ingest")
_CLICKHOUSE_SCHEMA_PATH = os.path.join(INGEST_DIR, "schema", "events_schema.sql")

# Session-unique, not a fixed "shadowtracer_test" - found the hard way
# (2026-10-08, see MEMORY/project_test_suite_db_race.md): a shared fixed
# name let this suite's session-start DROP+recreate race the ingest/backend
# suites' own identical fixtures when run concurrently against the same real
# cluster. The 2026-10-08 fix only applied this to TEST_CLICKHOUSE_DB below -
# TEST_POSTGRES_DB was still the fixed "shadowtracer_test" until now, so the
# same race was still live on Postgres. Generated once at conftest import
# time (= once per pytest session), dropped again at session end so it
# doesn't orphan a database per run.
TEST_POSTGRES_DB = f"shadowtracer_test_{uuid.uuid4().hex[:8]}"
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


# Without these, kafka_client_config_from_env() defaults to PLAINTEXT and every
# consumer/producer this suite starts silently fails to reach the SASL_SSL broker
# (the broker drops the connection at APIVERSION_QUERY). The suite then fails with
# "no incident appeared" because nothing is ever consumed - nothing to do with the
# code under test. The ingest conftest has carried this same fix since 2026-11-05
# (its "23 tests + 8 errors" note); it was never mirrored here. setdefault so a CI
# runner's own explicit values still win.
def _kafka_env_defaults() -> None:
    try:
        vals = _load_env()
    except OSError:
        return
    os.environ.setdefault("KAFKA_SECURITY_PROTOCOL", "SASL_SSL")
    os.environ.setdefault("KAFKA_SASL_USERNAME", "admin")
    os.environ.setdefault("KAFKA_SASL_PASSWORD", vals.get("KAFKA_ADMIN_PASSWORD", ""))
    os.environ.setdefault("KAFKA_SSL_CA_LOCATION",
                          os.path.join(os.path.dirname(ENV_PATH), "kafka-certs", "ca.crt"))


_kafka_env_defaults()


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
        "campaign_incidents, campaigns, tenants "
        "RESTART IDENTITY CASCADE"
    ))
    session.commit()
    session.close()


def insert_tenant(db, tenant_key: str) -> None:
    """Phase 5C Step 0: tenant_key now FKs into tenants (see
    PHASE3_DATA_PLATFORM.md) - every ad-hoc test tenant_key needs a real
    backing row before anything references it. `db`'s own TRUNCATE ...
    CASCADE (above) cleans this up after the test, no explicit teardown
    needed here."""
    db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:k, :k)"), {"k": tenant_key})
    db.commit()


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


@pytest.fixture(scope="session", autouse=True)
def _require_broker_round_trip(kafka_bootstrap):
    """Phase 7.4 Part A (item 3): fail the WHOLE session LOUDLY if the test clients cannot reach the
    broker or consume nothing - the exact silent failure that let the SASL_SSL/PLAINTEXT mismatch
    pass as a vacuous green (CI only static-checks a draining test file exists; it never runs this
    suite - see _kafka_env_defaults). Produces one probe message with the suite's own client config
    and requires it back, so a consumer that can't actually consume stops the run instead of letting
    every consume-based assertion below pass vacuously."""
    from confluent_kafka import Consumer, Producer
    cfg = kafka_client_config_from_env()
    probe_topic = alerts_topic_for_tenant(f"test-probe-{uuid.uuid4().hex[:8]}")
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **cfg})
    admin.create_topics([NewTopic(probe_topic, num_partitions=1, replication_factor=1)])[probe_topic].result(30)
    try:
        p = Producer({"bootstrap.servers": kafka_bootstrap, **cfg})
        p.produce(probe_topic, value=b"probe")
        if p.flush(15) != 0:
            pytest.exit(f"broker guard: could not PRODUCE to {probe_topic} - the test clients cannot "
                        f"reach the broker (PLAINTEXT against a SASL_SSL broker fails silently here; "
                        f"check KAFKA_SECURITY_PROTOCOL/SASL env)", returncode=1)
        c = Consumer({"bootstrap.servers": kafka_bootstrap, "group.id": f"probe-{uuid.uuid4().hex[:8]}",
                      "auto.offset.reset": "earliest", **cfg})
        c.subscribe([probe_topic])
        deadline = time.monotonic() + 30
        consumed = 0
        while time.monotonic() < deadline and consumed == 0:
            msg = c.poll(1.0)
            if msg is not None and not msg.error():
                consumed += 1
        c.close()
        if consumed == 0:
            pytest.exit(f"broker guard: produced to {probe_topic} but CONSUMED NOTHING within 30s - "
                        f"the test clients cannot consume, so every consume-based assertion in this "
                        f"suite would be vacuous (see _kafka_env_defaults)", returncode=1)
    finally:
        delete_topics_and_wait(admin, [probe_topic])
    yield


@pytest.fixture
def kafka_tenant_key(db):
    """Phase 5.6 Item 1: a fresh, random tenant per test - real tenants
    row AND real topic pair (kafka_topic below), since tenant identity
    is now bound to a topic, not just a header claim. Most tests only
    need kafka_topic; this is exposed separately for tests that need to
    reference the tenant_key itself."""
    tenant_key = f"test-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant_key)
    return tenant_key


@pytest.fixture
def kafka_topic(kafka_bootstrap, kafka_tenant_key):
    """Returns kafka_tenant_key's ALERTS topic name - same return shape
    (a plain topic-name string) every existing test already expects.
    Also provisions the matching dead-letter topic, since consumer.py
    now dead-letters to it unconditionally."""
    alerts_topic = alerts_topic_for_tenant(kafka_tenant_key)
    dead_letter_topic = dead_letter_topic_for_tenant(kafka_tenant_key)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    admin.create_topics([
        NewTopic(alerts_topic, num_partitions=1, replication_factor=1),
        NewTopic(dead_letter_topic, num_partitions=1, replication_factor=1),
    ])
    time.sleep(1)  # topic metadata propagation
    yield alerts_topic
    delete_topics_and_wait(admin, [alerts_topic, dead_letter_topic])


# Test consumers (writer.run / consumer.run) must only ever read this suite's
# own topics. Every test tenant key starts with "test-" (kafka_tenant_key);
# without this they pattern-subscribe to every lab tenant's topic from the
# earliest offset and dead-letter the lab's retained traffic before reaching
# their own messages.
TEST_TOPIC_PATTERN = r"^shadowtracer\.t\.test-.+\.alerts$"
