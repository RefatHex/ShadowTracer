import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Build the connection URL from POSTGRES_* env vars rather than committing
# a credential to alembic.ini. deploy/lab/.env sets these for local runs;
# a real deployment sets real env vars the same way.
pg_user = os.environ.get("POSTGRES_USER", "shadowtracer")
pg_password = os.environ.get("POSTGRES_PASSWORD", "")
pg_host = os.environ.get("POSTGRES_HOST", "127.0.0.1")
pg_port = os.environ.get("POSTGRES_PORT", "5432")
pg_db = os.environ.get("POSTGRES_DB", "shadowtracer")
config.set_main_option(
    "sqlalchemy.url",
    f"postgresql+psycopg2://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_db}",
)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = None

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


# Phase 5.6 Item 6: "backup, then upgrade; rollback = restore" - a
# down-migration is the exception now, not the rollback plan, after
# VERSIONING.md's real rollback test found a downgrade
# (8638c1abc22b) that silently drops operator data on a column it's
# dropping. Checking per-migration for an actual drop_column/drop_table
# call would need to re-derive it every time a migration is added and
# forgets to flag itself - cheaper and just as correct to require the
# flag for every downgrade, since nearly all of them (7 of 9) really are
# destructive; restore-from-backup is the documented safe path
# (docs/design/BACKUP_RESTORE.md) for the rest.
_cmd_opts = getattr(config, "cmd_opts", None)
if _cmd_opts is not None and getattr(_cmd_opts, "cmd", None) and _cmd_opts.cmd[0].__name__ == "downgrade":
    if not os.environ.get("SHADOWTRACER_FORCE_DESTRUCTIVE_DOWNGRADE"):
        raise SystemExit(
            "Refusing to run `alembic downgrade`: down-migrations can drop columns/tables "
            "and silently lose operator data (see docs/design/VERSIONING.md Sec 3's real "
            "example). The supported rollback is backup-then-restore, not downgrade - see "
            "docs/design/BACKUP_RESTORE.md. If you really mean to downgrade anyway, set "
            "SHADOWTRACER_FORCE_DESTRUCTIVE_DOWNGRADE=1 and re-run."
        )

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
