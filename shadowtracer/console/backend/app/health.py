"""Dependency health checks (Step 5). Each check is a small, independently
callable function so the readiness endpoint's logic (call every check,
report per-dependency status) is trivial and each check is unit-testable
without going through HTTP.
"""

import datetime

import clickhouse_connect
import httpx
from confluent_kafka import Consumer, ConsumerGroupTopicPartitions, TopicPartition
from confluent_kafka.admin import AdminClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import Settings


def check_postgres(db: Session) -> tuple[bool, str]:
    try:
        db.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready", report it
        return False, str(exc)


def check_clickhouse(settings: Settings) -> tuple[bool, str]:
    try:
        client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database=settings.clickhouse_database, connect_timeout=3,
        )
        client.query("SELECT 1")
        client.close()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def check_kafka(settings: Settings) -> tuple[bool, str]:
    try:
        admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers})
        metadata = admin.list_topics(timeout=3)
        if not metadata.brokers:
            return False, "no brokers in cluster metadata"
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def readiness_report(db: Session, settings: Settings) -> dict:
    checks = {
        "postgres": check_postgres(db),
        "clickhouse": check_clickhouse(settings),
        "kafka": check_kafka(settings),
    }
    all_ok = all(ok for ok, _ in checks.values())
    return {
        "ready": all_ok,
        "checks": {name: {"ok": ok, "detail": detail} for name, (ok, detail) in checks.items()},
    }


def shipper_lag_per_node(settings: Settings) -> dict:
    """Polls each configured shipper's metrics HTTP endpoint (see
    shadowtracer/ingest/shadowtracer_ingest/metrics.py). Best-effort - an
    unreachable shipper is reported as unreachable, not a crash."""
    result = {}
    for url in settings.shipper_metrics_urls:
        try:
            resp = httpx.get(url, timeout=2)
            resp.raise_for_status()
            result[url] = resp.json()
        except Exception as exc:  # noqa: BLE001
            result[url] = {"error": str(exc)}
    return result


def writer_consumer_lag(settings: Settings) -> dict:
    """Total lag (log end offset - committed offset) for the writer's
    consumer group, summed across partitions, plus per-partition detail."""
    try:
        admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers})
        group_futures = admin.list_consumer_group_offsets(
            [ConsumerGroupTopicPartitions(settings.writer_consumer_group)]
        )

        results = {}
        for group_id, future in group_futures.items():
            group_result = future.result(timeout=5)
            consumer = Consumer({
                "bootstrap.servers": settings.kafka_bootstrap_servers,
                "group.id": "shadowtracer-console-lag-check",
            })
            total_lag = 0
            partitions = []
            for tp in group_result.topic_partitions:
                low, high = consumer.get_watermark_offsets(TopicPartition(tp.topic, tp.partition), timeout=5)
                committed = tp.offset if tp.offset >= 0 else low
                lag = max(0, high - committed)
                total_lag += lag
                partitions.append({"topic": tp.topic, "partition": tp.partition, "committed": committed, "high_watermark": high, "lag": lag})
            consumer.close()
            results[group_id] = {"status": "ok", "total_lag": total_lag, "partitions": partitions}
        return results
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def last_event_time_per_tenant(settings: Settings) -> dict:
    try:
        client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database=settings.clickhouse_database, connect_timeout=3,
        )
        rows = client.query("SELECT tenant_id, max(time) AS last_event FROM events GROUP BY tenant_id").result_rows
        client.close()
        return {tenant_id: last_event.isoformat() if isinstance(last_event, datetime.datetime) else str(last_event)
                for tenant_id, last_event in rows}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
