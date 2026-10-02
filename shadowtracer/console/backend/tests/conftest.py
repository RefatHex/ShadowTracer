"""Fixtures. Per the project's guardrails, these hit the real lab
PostgreSQL and ClickHouse (deploy/lab/docker-compose.yml) over their
published host ports - never SQLite, never a mock."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "deploy", "lab", ".env")


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


# app.main creates its module-level `app` via load_settings() at IMPORT
# time (so `uvicorn app.main:app` works without a factory call) - that
# means required env vars must exist before any test module imports
# app.main, which happens at collection time, before fixtures run. Set
# them here, at conftest module scope, which always loads first.
_lab_env_for_import = _load_env()
os.environ.setdefault("JWT_SECRET", "conftest-import-time-placeholder-" + "x" * 32)
os.environ.setdefault("APP_DB_PASSWORD", _lab_env_for_import.get("APP_DB_PASSWORD", ""))
os.environ.setdefault("POSTGRES_HOST", "127.0.0.1")
os.environ.setdefault("POSTGRES_DB", _lab_env_for_import.get("POSTGRES_DB", "shadowtracer"))
os.environ.setdefault("CLICKHOUSE_USER", _lab_env_for_import.get("CLICKHOUSE_USER", ""))
os.environ.setdefault("CLICKHOUSE_PASSWORD", _lab_env_for_import.get("CLICKHOUSE_PASSWORD", ""))
os.environ.setdefault("CLICKHOUSE_HOST", "127.0.0.1")


@pytest.fixture(scope="session")
def lab_env():
    return _load_env()


@pytest.fixture(scope="session")
def database_url(lab_env):
    return (
        f"postgresql+psycopg2://{lab_env['POSTGRES_USER']}:{lab_env['POSTGRES_PASSWORD']}"
        f"@127.0.0.1:5432/{lab_env['POSTGRES_DB']}"
    )


@pytest.fixture(scope="session")
def engine(database_url):
    return create_engine(database_url, pool_pre_ping=True)


@pytest.fixture
def db(engine):
    """A real session against the real database, rolled back to a clean
    slate (truncating the auth tables) after every test so tests don't
    bleed into each other - cheaper than a transaction-per-test wrapper
    given these tests also exercise code that commits internally."""
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
    result = db.execute(tenants.insert().values(name="test-tenant").returning(tenants.c.id))
    db.commit()
    return result.scalar_one()


@pytest.fixture
def ch_env(lab_env):
    return lab_env
