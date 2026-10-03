"""SQLAlchemy Core table definitions mirroring the Alembic migrations in
shadowtracer/ingest/alembic/versions/. Core, not the ORM - these are
simple CRUD tables with no object-graph navigation worth the ORM's
session-identity-map complexity."""

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index,
    Integer, MetaData, String, Table, UniqueConstraint, func, text,
)

metadata = MetaData()

tenants = Table(
    "tenants", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False, unique=True),
    # Permanent identity, set once at creation and never exposed through
    # any update path - the shipper stamps events with this and the
    # access token carries it, so renaming `name` (display-only) can
    # never change which events a tenant sees.
    Column("tenant_key", String(64), nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_id", Integer, ForeignKey("tenants.id"), nullable=False),
    Column("email", String(255), nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("role", String(20), nullable=False),
    Column("is_active", Boolean, nullable=False, server_default=text("true")),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="users_role_check"),
    UniqueConstraint("tenant_id", "email", name="users_tenant_email_unique"),
)

refresh_tokens = Table(
    "refresh_tokens", metadata,
    Column("id", Integer, primary_key=True),
    Column("family_id", String(36), nullable=False),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True), nullable=True),
    Column("family_revoked", Boolean, nullable=False, server_default=text("false")),
    Index("ix_refresh_tokens_family_id", "family_id"),
)

login_attempts = Table(
    "login_attempts", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(45), nullable=False),
    Column("email", String(255), nullable=True),
    Column("success", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Index("ix_login_attempts_ip_created_at", "ip", "created_at"),
    Index("ix_login_attempts_email_created_at", "email", "created_at"),
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", Integer, primary_key=True),
    Column("actor", String(255), nullable=False),
    Column("tenant_id", Integer, nullable=True),
    Column("action", String(100), nullable=False),
    Column("target", String(255), nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("outcome", String(20), nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("row_hash", String(64), nullable=False),
)
