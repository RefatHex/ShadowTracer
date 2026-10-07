"""Settings from env vars or *_FILE paths (Docker secrets), per
DECISIONS.md Step 1. Refuses to start with a missing, placeholder, or
weak JWT secret - see validate_jwt_secret()."""

import os
from dataclasses import dataclass, field

MIN_JWT_SECRET_LENGTH = 32

# Values nobody should ship to production but everybody tries once.
PLACEHOLDER_SECRETS = {
    "changeme", "change_me", "change-me", "secret", "secretkey",
    "your-secret-key", "jwt-secret", "jwtsecret", "password",
    "insecure", "dev", "development", "test", "example",
}


class WeakSecretError(RuntimeError):
    """Raised at startup when JWT_SECRET is missing, a known placeholder,
    or too short. Never caught - this must stop the process."""


def _env_or_file(name: str) -> str | None:
    """Docker-secrets convention: NAME_FILE (a path) takes priority over
    NAME (a literal value) when both happen to be set."""
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        with open(file_path) as f:
            return f.read().strip()
    return os.environ.get(name)


def validate_jwt_secret(secret: str | None) -> str:
    if not secret:
        raise WeakSecretError("JWT_SECRET (or JWT_SECRET_FILE) is required and not set")
    if secret.strip().lower() in PLACEHOLDER_SECRETS:
        raise WeakSecretError(f"JWT_SECRET is a known placeholder value ({secret!r}) - generate a real one")
    if len(secret) < MIN_JWT_SECRET_LENGTH:
        raise WeakSecretError(
            f"JWT_SECRET is {len(secret)} characters, minimum is {MIN_JWT_SECRET_LENGTH} "
            "(generate with: openssl rand -base64 48)"
        )
    return secret


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    database_url: str
    clickhouse_host: str
    clickhouse_port: int
    clickhouse_user: str
    clickhouse_password: str
    clickhouse_database: str
    kafka_bootstrap_servers: str
    writer_consumer_group: str
    dead_letter_alert_threshold: int = 50
    lag_retention_alert_fraction: float = 0.25
    access_token_ttl_seconds: int = 900  # 15 minutes
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 7  # 7 days
    lockout_threshold: int = 5
    lockout_window_seconds: int = 60 * 15
    shipper_metrics_urls: list[str] = field(default_factory=list)
    cors_allow_origins: list[str] = field(default_factory=list)


def load_settings() -> Settings:
    jwt_secret = validate_jwt_secret(_env_or_file("JWT_SECRET"))

    # The app (and this CLI) connect as shadowtracer_app, a restricted role
    # created by the Phase 4 audit-log migration - NOT the table-owning
    # POSTGRES_USER, which keeps full rights (including UPDATE/DELETE on
    # audit_log) for migrations and operator/debugging access. See
    # DECISIONS.md and shadowtracer/ingest/alembic/versions/..._phase_4_audit_log...
    app_db_password = _env_or_file("APP_DB_PASSWORD")
    pg_host = os.environ.get("POSTGRES_HOST", "127.0.0.1")
    pg_port = os.environ.get("POSTGRES_PORT", "5432")
    pg_db = os.environ.get("POSTGRES_DB", "shadowtracer")
    if not app_db_password:
        raise WeakSecretError("APP_DB_PASSWORD (or APP_DB_PASSWORD_FILE) is required and not set")
    database_url = f"postgresql+psycopg2://shadowtracer_app:{app_db_password}@{pg_host}:{pg_port}/{pg_db}"

    ch_password = _env_or_file("CLICKHOUSE_PASSWORD")
    if not ch_password:
        raise WeakSecretError("CLICKHOUSE_PASSWORD (or CLICKHOUSE_PASSWORD_FILE) is required and not set")

    shipper_urls = [u for u in os.environ.get("SHIPPER_METRICS_URLS", "").split(",") if u]
    cors_origins = [o for o in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",") if o]

    return Settings(
        jwt_secret=jwt_secret,
        database_url=database_url,
        clickhouse_host=os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"),
        clickhouse_port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        clickhouse_user=_env_or_file("CLICKHOUSE_USER") or "shadowtracer",
        clickhouse_password=ch_password,
        clickhouse_database=os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"),
        kafka_bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
        writer_consumer_group=os.environ.get("KAFKA_WRITER_GROUP", "shadowtracer-writer"),
        dead_letter_alert_threshold=int(os.environ.get("DEAD_LETTER_ALERT_THRESHOLD", "50")),
        lag_retention_alert_fraction=float(os.environ.get("LAG_RETENTION_ALERT_FRACTION", "0.25")),
        access_token_ttl_seconds=int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900")),
        refresh_token_ttl_seconds=int(os.environ.get("REFRESH_TOKEN_TTL_SECONDS", str(60 * 60 * 24 * 7))),
        lockout_threshold=int(os.environ.get("LOCKOUT_THRESHOLD", "5")),
        lockout_window_seconds=int(os.environ.get("LOCKOUT_WINDOW_SECONDS", str(60 * 15))),
        shipper_metrics_urls=shipper_urls,
        cors_allow_origins=cors_origins,
    )
