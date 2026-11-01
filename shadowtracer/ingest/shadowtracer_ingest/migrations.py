"""Phase 5.6 Item 5: versioned ClickHouse migrations - the mechanism
docs/design/VERSIONING.md proposed (§2) after finding `apply_schema()`'s
`CREATE TABLE IF NOT EXISTS` silently no-ops any column added to an
already-existing table.

Numbered SQL files under schema/migrations/ (NNNN_description.sql, same
__DATABASE__/__KEEPER_PREFIX__ placeholder convention as
schema/events_schema.sql), applied in order, each one recorded in a
schema_migrations tracking table (one per database, same as the real
schema - a test database gets its own independent migration history).
Call apply_migrations() AFTER apply_schema() establishes the base tables.

Fails loudly on drift: if a migration file that's already recorded as
applied has since changed on disk (its content hash no longer matches
what was recorded when it ran), this raises rather than silently
re-running or ignoring the change - a migration is immutable once
applied, same discipline Alembic enforces for Postgres.
"""

import hashlib
import os
import re

from .clickhouse_schema import _LINE_COMMENT

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "schema", "migrations")
_FILENAME_RE = re.compile(r"^(\d+)_.*\.sql$")


class MigrationDriftError(RuntimeError):
    """A migration already recorded as applied no longer matches the
    file on disk. Never caught - this must stop the process, the same
    way a missing JWT secret does (app/config.py's WeakSecretError)."""


def _discover_migrations() -> list[tuple[int, str, str]]:
    """Returns (version, filename, sql_text) sorted by version. Raises
    on a malformed filename or a duplicate version number - a bad
    migration file is a build-time mistake to catch here, not a
    runtime surprise once it's already running against real data."""
    if not os.path.isdir(MIGRATIONS_DIR):
        return []
    found: dict[int, tuple[str, str]] = {}
    for filename in sorted(os.listdir(MIGRATIONS_DIR)):
        if not filename.endswith(".sql"):
            continue
        m = _FILENAME_RE.match(filename)
        if not m:
            raise RuntimeError(f"migration filename does not match NNNN_description.sql: {filename}")
        version = int(m.group(1))
        if version in found:
            raise RuntimeError(f"duplicate migration version {version}: {found[version][0]} and {filename}")
        with open(os.path.join(MIGRATIONS_DIR, filename)) as f:
            found[version] = (filename, f.read())
    return sorted((v, fn, sql) for v, (fn, sql) in found.items())


def _content_hash(sql_text: str) -> str:
    return hashlib.sha256(sql_text.encode()).hexdigest()


def _ensure_tracking_table(client, database: str) -> None:
    client.command(
        f"CREATE TABLE IF NOT EXISTS {database}.schema_migrations "
        "(version UInt32, filename String, content_hash String, applied_at DateTime DEFAULT now()) "
        "ENGINE = MergeTree ORDER BY version"
    )


def apply_migrations(client, database: str, keeper_prefix: str = "") -> list[int]:
    """Applies every migration newer than the highest version already
    recorded for this database, in order. Returns the list of newly
    applied version numbers (empty if nothing was pending). Call after
    apply_schema() - this assumes the base tables from
    schema/events_schema.sql already exist."""
    _ensure_tracking_table(client, database)
    migrations = _discover_migrations()

    applied = client.query(
        f"SELECT version, content_hash FROM {database}.schema_migrations"
    ).result_rows
    applied_hashes = dict(applied)
    max_applied = max(applied_hashes) if applied_hashes else 0

    newly_applied = []
    for version, filename, sql_text in migrations:
        rendered = sql_text.replace("__DATABASE__", database).replace("__KEEPER_PREFIX__", keeper_prefix)
        content_hash = _content_hash(rendered)

        if version in applied_hashes:
            if applied_hashes[version] != content_hash:
                raise MigrationDriftError(
                    f"migration {version} ({filename}) has changed since it was applied - "
                    f"recorded hash {applied_hashes[version]!r}, file now hashes to {content_hash!r}. "
                    "A migration is immutable once applied; fix by adding a NEW migration, "
                    "not editing this one."
                )
            continue  # already applied, unchanged - normal, not an error

        if version <= max_applied:
            # A lower-numbered migration than the highest already-applied
            # one, but never recorded - a real gap (e.g. a migration
            # added out of order after a later one already ran). Loud
            # failure, not a silent skip or a guess at intent.
            raise MigrationDriftError(
                f"migration {version} ({filename}) was never applied, but migration {max_applied} "
                "already was - migrations must apply in strict version order, this gap needs a human."
            )

        uncommented = _LINE_COMMENT.sub("", rendered)
        for statement in uncommented.split(";"):
            statement = statement.strip()
            if statement:
                client.command(statement)

        client.insert(
            "schema_migrations", [[version, filename, content_hash]],
            column_names=["version", "filename", "content_hash"], database=database,
        )
        newly_applied.append(version)

    return newly_applied
