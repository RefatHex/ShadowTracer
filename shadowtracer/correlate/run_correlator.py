#!/usr/bin/env python3
"""CLI entrypoint: the correlation engine's Kafka consumer (Phase 5A
Step 1).

Env vars:
  KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, KAFKA_GROUP_ID
  POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, APP_DB_PASSWORD
  SESSION_GAP_SECONDS (default 600), MAX_SPAN_SECONDS (default 14400)
  METRICS_PORT (default 9104)
"""

import logging
import os
import signal
import threading

from shadowtracer_correlate.consumer import run
from shadowtracer_correlate.metrics import Metrics, serve_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

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

run(
    bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
    topic=os.environ.get("KAFKA_TOPIC", "shadowtracer.events.raw"),
    group_id=os.environ.get("KAFKA_GROUP_ID", "shadowtracer-correlate"),
    database_url=database_url,
    metrics=metrics,
    stop_flag=stop_flag,
    session_gap_seconds=int(os.environ.get("SESSION_GAP_SECONDS", "600")),
    max_span_seconds=int(os.environ.get("MAX_SPAN_SECONDS", "14400")),
)
