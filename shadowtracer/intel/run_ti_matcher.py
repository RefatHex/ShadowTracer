"""ti-matcher service (THREAT_INTEL.md §3.1, shadowtracer_intel/matcher.py).

Env:
  KAFKA_BOOTSTRAP_SERVERS, KAFKA_GROUP_ID (default shadowtracer-ti-matcher), KAFKA_SECURITY_PROTOCOL,
  KAFKA_SASL_USERNAME, KAFKA_SASL_PASSWORD, KAFKA_SSL_CA_LOCATION (shadowtracer_ingest/kafka_security.py)
  POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, APP_DB_PASSWORD
  CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD, CLICKHOUSE_DATABASE
  TI_MATCHER_POLL_SECONDS (default 60): how often the IOC store version is checked
  TI_MATCHER_MAX_AGE_SECONDS (default 3600): reload at least this often (confidence decays)
"""
import logging
import os
import signal
import socket
import threading

import clickhouse_connect
from confluent_kafka import Consumer
from sqlalchemy import create_engine

from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.tenants import TenantCache
from shadowtracer_ingest.topics import ALERTS_TOPIC_PATTERN, tenant_from_alerts_topic
from shadowtracer_intel.matcher import Matcher
from shadowtracer_intel.sync import database_url


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    env = os.environ
    engine = create_engine(database_url(), pool_pre_ping=True)
    ch = clickhouse_connect.get_client(
        host=env.get("CLICKHOUSE_HOST", "127.0.0.1"), port=int(env.get("CLICKHOUSE_PORT", "8123")),
        username=env.get("CLICKHOUSE_USER", "default"), password=env.get("CLICKHOUSE_PASSWORD", ""),
        database=env.get("CLICKHOUSE_DATABASE", "shadowtracer"))
    consumer = Consumer({
        "bootstrap.servers": env["KAFKA_BOOTSTRAP_SERVERS"],
        "group.id": env.get("KAFKA_GROUP_ID", "shadowtracer-ti-matcher"),
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",           # a new tenant topic is matched from its first alert
        "topic.metadata.refresh.interval.ms": 10000,
        # librdkafka prefetches up to 64 MiB into its one consumer queue by default: on a
        # backlog that alone OOM-killed this 128m container in a loop (2026-11-06, 12
        # kills, never committing). 16 MiB keeps throughput and fits.
        "queued.max.messages.kbytes": 16384,
        "fetch.max.bytes": 8 * 1024 * 1024,
        **kafka_client_config_from_env(),
    })
    consumer.subscribe([ALERTS_TOPIC_PATTERN])
    tenants = TenantCache(engine)
    matcher = Matcher(consumer, engine, ch, tenant_from_alerts_topic, tenants.is_known, socket.gethostname(),
                      poll_s=int(env.get("TI_MATCHER_POLL_SECONDS", "60")),
                      max_age_s=int(env.get("TI_MATCHER_MAX_AGE_SECONDS", "3600")), stop=stop)
    matcher.clear_state()
    try:
        while not stop.is_set():
            matcher.step()
            matcher.log_stats()
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
