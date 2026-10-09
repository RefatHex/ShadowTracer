#!/usr/bin/env python3
"""CLI entrypoint: the Kafka consumer group that batch-inserts into
ClickHouse (Step 5).

Env vars:
  KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, KAFKA_GROUP_ID
  CLICKHOUSE_HOSTS ("host1:port1,host2:port2", tried in order - failover
    across replicas, see _FailoverClickHouse)
  CLICKHOUSE_USER, CLICKHOUSE_PASSWORD, CLICKHOUSE_DATABASE, METRICS_PORT
  POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, APP_DB_PASSWORD - Phase 5C
    Step 0's tenant-existence check (tenants.py); same role/convention as
    the correlator's own run_correlator.py.
"""

import logging
import os
import signal
import threading

from shadowtracer_ingest import writer
from shadowtracer_ingest.metrics import Metrics, serve_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

stop_flag = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop_flag.set())
signal.signal(signal.SIGINT, lambda *_: stop_flag.set())

metrics = Metrics()
serve_metrics(metrics, int(os.environ.get("METRICS_PORT", "9102")))

hosts_raw = os.environ.get("CLICKHOUSE_HOSTS", "127.0.0.1:8123,127.0.0.1:8124")
clickhouse_hosts = []
for hp in hosts_raw.split(","):
    host, port = hp.split(":")
    clickhouse_hosts.append((host, int(port)))

database_url = (
    f"postgresql+psycopg2://shadowtracer_app:{os.environ['APP_DB_PASSWORD']}"
    f"@{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:{os.environ.get('POSTGRES_PORT', '5432')}"
    f"/{os.environ.get('POSTGRES_DB', 'shadowtracer')}"
)

writer.run(
    bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
    topic=os.environ.get("KAFKA_TOPIC", "shadowtracer.events.raw"),
    group_id=os.environ.get("KAFKA_GROUP_ID", "shadowtracer-writer"),
    clickhouse_hosts=clickhouse_hosts,
    clickhouse_user=os.environ["CLICKHOUSE_USER"],
    clickhouse_password=os.environ["CLICKHOUSE_PASSWORD"],
    clickhouse_database=os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"),
    database_url=database_url,
    metrics=metrics,
    stop_flag=stop_flag,
)
