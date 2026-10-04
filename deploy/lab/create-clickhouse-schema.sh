#!/usr/bin/env bash
# Applies the one ClickHouse schema source
# (shadowtracer/ingest/schema/events_schema.sql, Phase 5A Step 0) to the
# lab's real "shadowtracer" database - idempotent (every CREATE is IF
# NOT EXISTS), safe to re-run on every bring-up. Previously this schema
# was applied by hand, once, with no reproducible record of it - a
# from-scratch lab bring-up would start with no events table at all.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

INGEST_DIR="../../shadowtracer/ingest"
"$INGEST_DIR/.venv/bin/python3" -c "
import sys
sys.path.insert(0, '$INGEST_DIR')
import clickhouse_connect
from shadowtracer_ingest.clickhouse_schema import apply_schema

client = clickhouse_connect.get_client(
    host='127.0.0.1', port=8123,
    username='$CLICKHOUSE_USER', password='$CLICKHOUSE_PASSWORD',
)
apply_schema(client, database='shadowtracer', keeper_prefix='')
client.close()
print('schema applied to shadowtracer')
"
