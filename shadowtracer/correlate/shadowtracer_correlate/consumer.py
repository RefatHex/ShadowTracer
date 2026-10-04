"""The correlation engine's Kafka consumer loop (Phase 5A Step 1): a
second, independent consumer group on the same raw events topic the
writer reads - never ClickHouse, which holds alert content but no
incident state. Offsets are committed only after the PostgreSQL write for
that message has actually succeeded (process_event's transaction
committed) - if the process dies in between, the next consumer in the
group re-reads the same message on restart and reprocesses it, which
process_event makes a safe no-op (see its own docstring).

A message that fails to normalise (genuinely malformed JSON) is counted
and its offset still committed - never retried forever, same policy as
shadowtracer_ingest.writer. A message that normalises but can't be
correlated by any basis (no source IP, user, or rule group at all) is
also counted and committed - there's nothing to retry there either.
A message that fails during process_event itself (e.g. a transient
database error) is NOT committed, so it's redelivered on restart -
that's the one case where retrying is the right answer.
"""

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))
from shadowtracer_ingest.normalizer import normalize_alert  # noqa: E402

from confluent_kafka import Consumer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .correlator import DEFAULT_MAX_SPAN_SECONDS, DEFAULT_SESSION_GAP_SECONDS, process_event
from .metrics import Metrics

logger = logging.getLogger(__name__)

POLL_TIMEOUT_SECONDS = 1.0


def run(
    bootstrap_servers: str,
    topic: str,
    group_id: str,
    database_url: str,
    metrics: Metrics,
    stop_flag,
    started_flag=None,
    session_gap_seconds: int = DEFAULT_SESSION_GAP_SECONDS,
    max_span_seconds: int = DEFAULT_MAX_SPAN_SECONDS,
):
    consumer = Consumer({
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([topic])

    engine = create_engine(database_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    if started_flag is not None:
        started_flag.set()

    try:
        while not stop_flag.is_set():
            msg = consumer.poll(POLL_TIMEOUT_SECONDS)
            if msg is None:
                continue
            if msg.error():
                metrics.incr("messages_failed")
                continue

            tenant_key = None
            for k, v in (msg.headers() or []):
                if k == "tenant_id":  # header name predates tenant_key (Phase 4 follow-up 1); the VALUE is the tenant_key
                    tenant_key = v.decode()
                    break

            try:
                event = normalize_alert(msg.value().decode(), tenant_key or "")
            except Exception:
                metrics.incr("messages_failed")
                consumer.commit(msg)
                continue

            db = Session()
            try:
                result = process_event(db, event, session_gap_seconds, max_span_seconds)
            except Exception:
                logger.exception("process_event failed for alert %s - not committing, will retry", event.alert_id)
                metrics.incr("process_errors")
                continue
            finally:
                db.close()

            metrics.incr(f"alerts_{result.status}")
            consumer.commit(msg)
    finally:
        consumer.close()
