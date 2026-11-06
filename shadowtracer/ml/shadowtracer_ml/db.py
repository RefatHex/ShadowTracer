"""Connections from env (lab: deploy/lab/.env; inside containers: compose env)."""
import os

from sqlalchemy import create_engine


def database_url(env=os.environ) -> str:
    return (f"postgresql+psycopg2://{env.get('POSTGRES_USER', 'shadowtracer_app')}:"
            f"{env.get('POSTGRES_PASSWORD') or env.get('APP_DB_PASSWORD', '')}@"
            f"{env.get('POSTGRES_HOST', '127.0.0.1')}:{env.get('POSTGRES_PORT', '5432')}/{env.get('POSTGRES_DB', 'shadowtracer')}")


def engine(env=os.environ):
    return create_engine(database_url(env), pool_pre_ping=True)


def clickhouse(env=os.environ):
    import clickhouse_connect
    return clickhouse_connect.get_client(
        host=env.get("CLICKHOUSE_HOST", "127.0.0.1"), port=int(env.get("CLICKHOUSE_PORT", "8123")),
        username=env.get("CLICKHOUSE_USER", "default"), password=env.get("CLICKHOUSE_PASSWORD", ""),
        database=env.get("CLICKHOUSE_DATABASE", "shadowtracer"))


def test_tenant(env=os.environ) -> str:
    """All 7.0 activity, replays and labels live in the TEST tenant only."""
    t = env.get("TEST_TENANT_KEY")
    if not t:
        raise SystemExit("TEST_TENANT_KEY is not set (deploy/lab/.env)")
    return t
