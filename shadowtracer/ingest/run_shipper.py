#!/usr/bin/env python3
"""CLI entrypoint: one shipper process per manager node (Step 3).

Env vars:
  TENANT_ID, MANAGER_NAME, ALERTS_PATH (required)
  ARCHIVES_PATH (optional - only set for tenants with raw events enabled)
  KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, OFFSET_FILE, METRICS_PORT
"""

import logging
import os
import signal
import threading

from shadowtracer_ingest import shipper
from shadowtracer_ingest.metrics import Metrics, serve_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

stop_flag = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop_flag.set())
signal.signal(signal.SIGINT, lambda *_: stop_flag.set())

metrics = Metrics()
serve_metrics(metrics, int(os.environ.get("METRICS_PORT", "9101")))

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
)
