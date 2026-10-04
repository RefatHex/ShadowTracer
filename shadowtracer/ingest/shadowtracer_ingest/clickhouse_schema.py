"""The one ClickHouse schema source (Phase 5A Step 0), rendered for
either the lab's real database or an isolated test database by
substituting __DATABASE__ and __KEEPER_PREFIX__ in
schema/events_schema.sql - see that file's header for why both
placeholders exist and why the engine stays Replicated even for tests.

Only usable from within shadowtracer/ingest's own venv - console backend
tests read this same file directly by path instead of importing this
module, since they run in a separate venv (see that conftest.py).
"""

import os
import re

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "schema", "events_schema.sql")

# Strips a `-- ...` line comment (to end of line) from each line - applied
# only when splitting into statements, never to the text returned by
# render_schema, which keeps comments for anyone reading the rendered
# SQL. This schema's prose comments routinely contain semicolons of their
# own ("safe for dedup; a retried produce..."), which a naive split on
# every literal `;` in the raw text would wrongly treat as a statement
# boundary - found the hard way when that split a CREATE TABLE's column
# list in half. ClickHouse's own CLI parses comments correctly; this
# approximates that without a real SQL parser, good enough for the
# fixed, hand-written statements in this one file.
_LINE_COMMENT = re.compile(r"--.*$", re.MULTILINE)


def render_schema(database: str, keeper_prefix: str = "") -> str:
    with open(SCHEMA_PATH) as f:
        sql = f.read()
    return sql.replace("__DATABASE__", database).replace("__KEEPER_PREFIX__", keeper_prefix)


def apply_schema(client, database: str, keeper_prefix: str = "") -> None:
    """Runs every statement in the rendered schema via `client.command`
    (a clickhouse_connect client) - all statements are IF NOT EXISTS, so
    this is safe to re-run against an already-provisioned database."""
    uncommented = _LINE_COMMENT.sub("", render_schema(database, keeper_prefix))
    for statement in uncommented.split(";"):
        statement = statement.strip()
        if statement:
            client.command(statement)
