#!/usr/bin/env python3
"""CLI entrypoint: one shipper process per manager node (Step 3).

Env vars:
  TENANT_ID, MANAGER_NAME, ALERTS_PATH (required)
  ARCHIVES_PATH (optional - only set for tenants with raw events enabled)
  KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, OFFSET_FILE, METRICS_PORT
  CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD,
  CLICKHOUSE_DATABASE - optional; a dead-lettered line always goes to the
  Kafka dead-letter topic regardless, these only add the queryable
  per-tenant count (shadowtracer_ingest/dead_letter.py). Omit all of them
  to run without a ClickHouse dependency at all (e.g. in a test).
"""

import logging
import os
import signal
import threading

import clickhouse_connect

from shadowtracer_ingest import shipper
from shadowtracer_ingest.metrics import Metrics, serve_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

stop_flag = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop_flag.set())
signal.signal(signal.SIGINT, lambda *_: stop_flag.set())

metrics = Metrics()
serve_metrics(metrics, int(os.environ.get("METRICS_PORT", "9101")))

ch_client = None
if os.environ.get("CLICKHOUSE_HOST"):
    ch_client = clickhouse_connect.get_client(
        host=os.environ["CLICKHOUSE_HOST"], port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        username=os.environ.get("CLICKHOUSE_USER", "default"), password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        database=os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"),
    )

shipper.run(
    tenant_id=os.environ["TENANT_ID"],
    manager_name=os.environ["MANAGER_NAME"],
    alerts_path=os.environ["ALERTS_PATH"],
    archives_path=os.environ.get("ARCHIVES_PATH") or None,
    bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
    topic=os.environ.get("KAFKA_TOPIC", "shadowtracer.events.raw"),
    offset_file=os.environ.get("OFFSET_FILE", "/tmp/shipper-offsets.json"),
    metrics=metrics,
    stop_flag=stop_flag,
    ch_client=ch_client,
)
