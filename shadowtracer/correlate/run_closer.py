#!/usr/bin/env python3
"""CLI entrypoint: the incident closer's polling loop (Phase 5A Step 1/3).
Safe to run several replicas of - see closer.py's advisory-lock docstring.

Env vars:
  POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, APP_DB_PASSWORD
  CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD, CLICKHOUSE_DATABASE
  SESSION_GAP_SECONDS (default 600)
  INTERNAL_IP_RANGES - comma-separated CIDRs, e.g. "10.0.0.0/8,192.168.0.0/16"
  CLOSER_POLL_INTERVAL_SECONDS (default 30)
  METRICS_PORT (default 9105)
"""

import os
import signal
import threading

from shadowtracer_correlate.closer_loop import run
from shadowtracer_correlate.metrics import Metrics, serve_metrics

stop_flag = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop_flag.set())
signal.signal(signal.SIGINT, lambda *_: stop_flag.set())

metrics = Metrics()
serve_metrics(metrics, int(os.environ.get("METRICS_PORT", "9105")))

database_url = (
    f"postgresql+psycopg2://shadowtracer_app:{os.environ['APP_DB_PASSWORD']}"
    f"@{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:{os.environ.get('POSTGRES_PORT', '5432')}"
    f"/{os.environ.get('POSTGRES_DB', 'shadowtracer')}"
)

internal_ranges = [r.strip() for r in os.environ.get("INTERNAL_IP_RANGES", "").split(",") if r.strip()]

run(
    database_url=database_url,
    clickhouse_host=os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"),
    clickhouse_port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
    clickhouse_user=os.environ["CLICKHOUSE_USER"],
    clickhouse_password=os.environ["CLICKHOUSE_PASSWORD"],
    clickhouse_database=os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"),
    session_gap_seconds=int(os.environ.get("SESSION_GAP_SECONDS", "600")),
    internal_ranges=internal_ranges,
    metrics=metrics,
    stop_flag=stop_flag,
    poll_interval_seconds=float(os.environ.get("CLOSER_POLL_INTERVAL_SECONDS", "30")),
)
