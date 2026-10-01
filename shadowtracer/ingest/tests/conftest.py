"""Shared fixtures. Per the Phase 3 guardrails, every test here hits the
real lab Kafka/ClickHouse/Postgres (deploy/lab/docker-compose.yml) over
their published host ports - never a mock, never SQLite."""

import os
import time
import uuid

import clickhouse_connect
import psycopg2
import pytest
from confluent_kafka.admin import AdminClient, NewTopic

ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "deploy", "lab", ".env")


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


@pytest.fixture(scope="session")
def lab_env():
    return _load_env()


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
def ch_client(lab_env):
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database="shadowtracer",
    )
    yield client
    client.close()


@pytest.fixture
def pg_conn(lab_env):
    conn = psycopg2.connect(
        host="127.0.0.1", port=5432,
        user=lab_env["POSTGRES_USER"], password=lab_env["POSTGRES_PASSWORD"],
        dbname=lab_env["POSTGRES_DB"],
    )
    yield conn
    conn.close()


FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "real_alerts_4.14.8.jsonl")


@pytest.fixture
def real_alert_lines():
    with open(FIXTURES_PATH) as f:
        return [line.rstrip("\n") for line in f if line.strip()]
