"""Fixtures. Per the project's guardrails, these hit real PostgreSQL and
ClickHouse (deploy/lab/docker-compose.yml) over their published host
ports - never SQLite, never a mock. The one exception is the database
*names* themselves: tests run against isolated shadowtracer_test
databases (both Postgres and ClickHouse), created and wiped fresh every
session, never the lab's real ones - see
_refuse_if_pointed_at_lab_database.
"""

import os
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import clickhouse_connect
import psycopg2
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "deploy", "lab", ".env")
INGEST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ingest")
_CLICKHOUSE_TEST_SCHEMA_PATH = os.path.join(INGEST_DIR, "schema", "test_only_clickhouse_schema.sql")

TEST_POSTGRES_DB = "shadowtracer_test"
TEST_CLICKHOUSE_DB = "shadowtracer_test"
# The real ClickHouse database name - hardcoded (not read from .env)
# because it's a fixed constant everywhere else in this project too
# (docker-compose.yml's CLICKHOUSE_DB, config.py's default, schema/*.sql);
# there's no env var for it to drift out of sync with.
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
    check-project.sh, which greps for this function's name): if either
    test database name ever resolves to the lab's real one - a future
    edit, a stray env override - refuse outright instead of silently
    touching production data."""
    if TEST_POSTGRES_DB == lab_postgres_db:
        pytest.exit(
            f"refusing to run: test Postgres database {TEST_POSTGRES_DB!r} "
            f"is the lab's real database - tests must never touch lab data",
            returncode=1,
        )
    if TEST_CLICKHOUSE_DB == LAB_CLICKHOUSE_DB:
        pytest.exit(
            f"refusing to run: test ClickHouse database {TEST_CLICKHOUSE_DB!r} "
            f"is the lab's real database - tests must never touch lab data",
            returncode=1,
        )


# app.main creates its module-level `app` via load_settings() at IMPORT
# time (so `uvicorn app.main:app` works without a factory call) - that
# means required env vars must exist before any test module imports
# app.main, which happens at collection time, before fixtures run. Set
# them here, at conftest module scope, which always loads first. POSTGRES_DB
# points at the isolated test database, never the lab's real one, even for
# this early, import-time-only construction (see TEST_POSTGRES_DB's guard).
_lab_env_for_import = _load_env()
os.environ.setdefault("JWT_SECRET", "conftest-import-time-placeholder-" + "x" * 32)
os.environ.setdefault("APP_DB_PASSWORD", _lab_env_for_import.get("APP_DB_PASSWORD", ""))
os.environ.setdefault("POSTGRES_HOST", "127.0.0.1")
os.environ.setdefault("POSTGRES_DB", TEST_POSTGRES_DB)
os.environ.setdefault("CLICKHOUSE_USER", _lab_env_for_import.get("CLICKHOUSE_USER", ""))
os.environ.setdefault("CLICKHOUSE_PASSWORD", _lab_env_for_import.get("CLICKHOUSE_PASSWORD", ""))
os.environ.setdefault("CLICKHOUSE_HOST", "127.0.0.1")


@pytest.fixture(scope="session")
def lab_env():
    return _load_env()


@pytest.fixture(scope="session")
def test_postgres_db():
    return TEST_POSTGRES_DB


@pytest.fixture(scope="session")
def test_clickhouse_db():
    return TEST_CLICKHOUSE_DB


@pytest.fixture(scope="session", autouse=True)
def _isolated_postgres_test_database(lab_env):
    """Drops and recreates shadowtracer_test fresh at the start of every
    test session, then runs the real Alembic migrations against it - same
    schema and shadowtracer_app role/grants as the lab, on a database the
    lab never uses."""
    _refuse_if_pointed_at_lab_database(lab_postgres_db=lab_env["POSTGRES_DB"])

    admin_conn = psycopg2.connect(
        host="127.0.0.1", port=5432,
        user=lab_env["POSTGRES_USER"], password=lab_env["POSTGRES_PASSWORD"],
        dbname=lab_env["POSTGRES_DB"],
    )
    admin_conn.autocommit = True  # DROP/CREATE DATABASE can't run inside a transaction
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


@pytest.fixture(scope="session", autouse=True)
def _isolated_clickhouse_test_database(lab_env):
    """Drops and recreates shadowtracer_test fresh at the start of every
    test session - see schema/test_only_clickhouse_schema.sql's header for
    why it's Replicated/ON CLUSTER under a different Keeper path than the
    real tables, not a plain MergeTree."""
    _refuse_if_pointed_at_lab_database(lab_postgres_db=lab_env["POSTGRES_DB"])

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
    """A real session against the isolated test database, rolled back to
    a clean slate (truncating the auth tables) after every test so tests
    don't bleed into each other - cheaper than a transaction-per-test
    wrapper given these tests also exercise code that commits internally."""
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.rollback()
    session.execute(text(
        "TRUNCATE TABLE audit_log, refresh_tokens, login_attempts, users, tenants RESTART IDENTITY CASCADE"
    ))
    session.commit()
    session.close()


@pytest.fixture
def tenant_id(db):
    from app.models import tenants
    result = db.execute(
        tenants.insert().values(name="test-tenant", tenant_key="test-tenant-key").returning(tenants.c.id)
    )
    db.commit()
    return result.scalar_one()


@pytest.fixture
def ch_env(lab_env):
    return lab_env
