#!/usr/bin/env python3
"""CLI entrypoint: the correlation engine's Kafka consumer (Phase 5A
Step 1).

Env vars:
  KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, KAFKA_GROUP_ID
  POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, APP_DB_PASSWORD
  SESSION_GAP_SECONDS (default 600), MAX_SPAN_SECONDS (default 14400)
  METRICS_PORT (default 9104)
  CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD,
  CLICKHOUSE_DATABASE - optional; a dead-lettered event always goes to the
  Kafka dead-letter topic regardless, these only add the queryable
  per-tenant count (shadowtracer_ingest/dead_letter.py). Omit all of them
  to run without a ClickHouse dependency at all (e.g. in a test).
  SEQUENCES_DIR (default sequences/, relative to this file - Phase 5B
  Step 4) - sequence detection is simply not evaluated if this is unset
  or ch_client isn't configured (see consumer.run()'s own docstring).
"""

import logging
import os
import signal
import threading

import clickhouse_connect

from shadowtracer_correlate.consumer import run
from shadowtracer_correlate.metrics import Metrics, serve_metrics
from shadowtracer_ingest.retry import retry_with_backoff

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

stop_flag = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop_flag.set())
signal.signal(signal.SIGINT, lambda *_: stop_flag.set())

metrics = Metrics()
serve_metrics(metrics, int(os.environ.get("METRICS_PORT", "9104")))

database_url = (
    f"postgresql+psycopg2://shadowtracer_app:{os.environ['APP_DB_PASSWORD']}"
    f"@{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:{os.environ.get('POSTGRES_PORT', '5432')}"
    f"/{os.environ.get('POSTGRES_DB', 'shadowtracer')}"
)

clickhouse_database = os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer")
# Startup race (found running the real lab stack cold, see
# PHASE5C_SIGMA.md §11): ClickHouse isn't guaranteed ready yet even after
# its container is "started" - retry forever instead of crashing.
ch_client = None
if os.environ.get("CLICKHOUSE_HOST"):
    ch_client = retry_with_backoff(
        lambda: clickhouse_connect.get_client(
            host=os.environ["CLICKHOUSE_HOST"], port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
            username=os.environ.get("CLICKHOUSE_USER", "default"), password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=clickhouse_database,
        ),
        max_attempts=None, base_delay=1.0, max_delay=30.0, stop_flag=stop_flag,
        on_retry=lambda attempt, exc: logger.warning(
            "ClickHouse connect attempt %d failed (transient - retrying): %s", attempt, exc,
        ),
    )

sequences_dir = os.environ.get(
    "SEQUENCES_DIR", os.path.join(os.path.dirname(__file__), "sequences")
)

run(
    bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
    topic=os.environ.get("KAFKA_TOPIC", "shadowtracer.events.raw"),
    group_id=os.environ.get("KAFKA_GROUP_ID", "shadowtracer-correlate"),
    database_url=database_url,
    metrics=metrics,
    stop_flag=stop_flag,
    session_gap_seconds=int(os.environ.get("SESSION_GAP_SECONDS", "600")),
    max_span_seconds=int(os.environ.get("MAX_SPAN_SECONDS", "14400")),
    ch_client=ch_client,
    clickhouse_database=clickhouse_database,
    sequences_dir=sequences_dir if os.path.isdir(sequences_dir) else None,
)
