"""Shared fixtures. Per the Phase 3 guardrails, every test here hits the
real lab Kafka/ClickHouse (deploy/lab/docker-compose.yml) over their
published host ports - never a mock, never SQLite. The one exception is
the database *names* themselves: ClickHouse tests run against an isolated
shadowtracer_test database (created and wiped fresh every session), never
the lab's real one - see _refuse_if_pointed_at_lab_clickhouse_database.
Kafka topics are already isolated per-test (a unique name each time, see
kafka_topic below), so no separate "test cluster" is needed there.
"""

import os
import time
import uuid

import clickhouse_connect
import pytest
from confluent_kafka.admin import AdminClient, NewTopic

ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "deploy", "lab", ".env")

# The real, production/lab ClickHouse database name - hardcoded here (not
# read from .env) because it's a fixed constant everywhere else in this
# project too (docker-compose.yml's CLICKHOUSE_DB, config.py's default,
# the schema/*.sql files) - there is no env var for it to drift out of
# sync with.
LAB_CLICKHOUSE_DB = "shadowtracer"
TEST_CLICKHOUSE_DB = "shadowtracer_test"

_CLICKHOUSE_TEST_SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "schema", "test_only_clickhouse_schema.sql"
)


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


def _refuse_if_pointed_at_lab_clickhouse_database() -> None:
    """Hard guard, checked before any test runs (and statically by
    check-project.sh, which greps for this function's name): if
    TEST_CLICKHOUSE_DB ever resolves to the lab's real database name -
    a future edit, a stray env override - refuse outright instead of
    silently truncating/inserting into production data."""
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
def _isolated_clickhouse_test_database(lab_env):
    """Drops and recreates shadowtracer_test fresh at the start of every
    test session, then applies the test-only schema (see that file's
    header for why it's still Replicated/ON CLUSTER, just under a
    different Keeper path prefix than the real tables)."""
    _refuse_if_pointed_at_lab_clickhouse_database()

    admin_client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
    )
    admin_client.command(f"DROP DATABASE IF EXISTS {TEST_CLICKHOUSE_DB} ON CLUSTER lab_cluster")
    # A fresh, never-before-used Keeper path suffix every session - see
    # the schema file's header for why a fixed path would race this same
    # DROP's asynchronous Keeper cleanup.
    keeper_session = uuid.uuid4().hex[:8]
    with open(_CLICKHOUSE_TEST_SCHEMA_PATH) as f:
        schema_sql = f.read().replace("__KEEPER_SESSION__", keeper_session)
    for statement in schema_sql.split(";"):
        statement = statement.strip()
        if statement:
            admin_client.command(statement)
    admin_client.close()


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


@pytest.fixture
def ch_client(lab_env, _isolated_clickhouse_test_database):
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database=TEST_CLICKHOUSE_DB,
    )
    yield client
    client.close()


FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "real_alerts_4.14.8.jsonl")


@pytest.fixture
def real_alert_lines():
    with open(FIXTURES_PATH) as f:
        return [line.rstrip("\n") for line in f if line.strip()]
