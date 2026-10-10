"""The correlation engine's Kafka consumer loop (Phase 5A Step 1): a
second, independent consumer group on the same raw events topic the
writer reads - never ClickHouse, which holds alert content but no
incident state. Offsets are committed only after the PostgreSQL write for
that message has actually succeeded (process_event's transaction
committed) - if the process dies in between, the next consumer in the
group re-reads the same message on restart and reprocesses it, which
process_event makes a safe no-op (see its own docstring).

No single event may stop the pipeline - two distinct failure kinds, never
confused with each other (same split as shadowtracer_ingest.writer):

- PERMANENT (bad data - a message that fails to normalise, or one
  process_event flags via correlator.UnparseableEvent, so far just a bad
  timestamp): counted, dead-lettered (dead_letter.send_to_dead_letter),
  and its offset committed - never retried, since retrying bytes that can
  never parse differently just wedges the partition forever (found for
  real in Phase 5A VERIFY - a single bad timestamp stopped this consumer
  from processing anything else on that partition until this was fixed).
- TRANSIENT (any other process_event failure, e.g. a database outage):
  retried in place with capped exponential backoff, forever, never
  dead-lettered and never committed - redelivering it to a DIFFERENT
  consumer on restart would be pointless when this one can just keep
  retrying the same message until the database comes back. stop_flag
  interrupts the wait for a graceful shutdown (message stays uncommitted,
  genuinely redelivered on restart then).
"""

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))
from shadowtracer_ingest.dead_letter import send_to_dead_letter  # noqa: E402
from shadowtracer_ingest.normalizer import normalize_alert  # noqa: E402
from shadowtracer_ingest.tenants import TenantCache  # noqa: E402

from confluent_kafka import Consumer, Producer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .correlator import DEFAULT_MAX_SPAN_SECONDS, DEFAULT_SESSION_GAP_SECONDS, UnparseableEvent, process_event
from .sequences import DEFAULT_LATENESS_SECONDS
from .metrics import Metrics
from .sequences import load_sequences

logger = logging.getLogger(__name__)

POLL_TIMEOUT_SECONDS = 1.0
PROCESS_BASE_DELAY_SECONDS = 1.0
PROCESS_MAX_DELAY_SECONDS = 30.0


def _dead_letter_with_retry(stop_flag, metrics, **kwargs) -> bool:
    """Returns True once the dead-letter write succeeds durably (via the
    Kafka dead-letter topic - send_to_dead_letter only ever raises for
    that half, since a ClickHouse-side failure is already caught inside
    it), retrying forever with backoff in between - same as any other
    transient infra failure, so a permanently bad event is never left
    with no durable record anywhere. Returns False only if stop_flag
    fires mid-retry (graceful shutdown) - the caller must NOT commit the
    triggering message's offset in that case, so it's genuinely
    redelivered and retried again after restart."""
    attempt = 0
    while True:
        try:
            send_to_dead_letter(metrics=metrics, **kwargs)
            return True
        except Exception as exc:  # noqa: BLE001 - the Kafka publish itself failing is transient, not bad data
            attempt += 1
            logger.warning("dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc)
            delay = min(PROCESS_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), PROCESS_MAX_DELAY_SECONDS)
            if stop_flag.wait(delay):
                return False


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
    ch_client=None,
    clickhouse_database: str | None = None,
    sequences_dir: str | None = None,
    sequence_lateness_seconds: float = DEFAULT_LATENESS_SECONDS,
):
    """ch_client is optional (None is fine, e.g. in tests that don't care
    about dead-letter counts) - a dead-lettered event still always goes to
    the Kafka dead-letter topic either way; ch_client only adds the
    queryable-per-tenant-count side of send_to_dead_letter.

    Phase 5B Step 4: sequences_dir/clickhouse_database are optional too -
    omitted, sequence detection is simply not evaluated (ch_client alone
    isn't enough; see process_event's own docstring for why both are
    required together)."""
    sequences = load_sequences(sequences_dir) if sequences_dir else None
    consumer = Consumer({
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([topic])

    engine = create_engine(database_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    dead_letter_producer = Producer({"bootstrap.servers": bootstrap_servers})
    # Phase 5C Step 0: a forged/stale/deleted tenant_key must never create
    # silent orphaned incidents - see tenants.py's own docstring for why
    # this is a periodically-refreshed cache, not a query per message.
    tenant_cache = TenantCache(engine)

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

            # errors="replace", never strict: invalid UTF-8 in a Kafka
            # message value must not crash the consumer loop - replaced
            # bytes fail JSON parsing naturally below and get
            # dead-lettered there.
            raw_line = msg.value().decode("utf-8", errors="replace")
            source_location = f"{msg.topic()}:{msg.partition()}:{msg.offset()}"

            # Phase 5C Step 0: checked before normalize_alert, same
            # permanent-bad-data path - never retried, since this
            # tenant_key isn't about to start existing mid-retry any more
            # than a bad timestamp is.
            if not tenant_cache.is_known(tenant_key or ""):
                metrics.incr("messages_failed")
                if not _dead_letter_with_retry(
                    stop_flag, metrics,
                    kafka_producer=dead_letter_producer, ch_client=ch_client, tenant_key=tenant_key,
                    component="correlator", source_location=source_location,
                    error="unknown_tenant", raw_event=raw_line,
                ):
                    continue  # shutting down mid-retry - don't commit, this message is genuinely redelivered on restart
                consumer.commit(msg)
                continue

            try:
                event = normalize_alert(raw_line, tenant_key or "")
            except Exception as exc:  # noqa: BLE001 - permanent, bad data: dead-letter and move on, never retried
                metrics.incr("messages_failed")
                if not _dead_letter_with_retry(
                    stop_flag, metrics,
                    kafka_producer=dead_letter_producer, ch_client=ch_client, tenant_key=tenant_key,
                    component="correlator", source_location=source_location,
                    error=f"{type(exc).__name__}: {exc}", raw_event=raw_line,
                ):
                    continue  # shutting down mid-retry - don't commit, this message is genuinely redelivered on restart
                consumer.commit(msg)
                continue

            # Retries the SAME message in place, forever, with capped
            # backoff, for a transient process_event failure (e.g. the
            # database is briefly unreachable) - never dead-lettered, since
            # by this point the event is known-good data. A permanently
            # malformed field (UnparseableEvent) is the one exception this
            # loop does NOT retry: it's bad data, so it's dead-lettered
            # immediately instead, same as a normalize_alert failure above.
            attempt_n = 0
            result = None
            while True:
                db = Session()
                try:
                    result = process_event(
                        db, event, session_gap_seconds, max_span_seconds,
                        sequences=sequences, ch_client=ch_client, clickhouse_database=clickhouse_database,
                        sequence_lateness_seconds=sequence_lateness_seconds,
                    )
                except UnparseableEvent:
                    db.close()
                    logger.warning("alert %s has a permanently malformed field - dead-lettering, not retrying", event.alert_id)
                    metrics.incr("messages_failed")
                    if not _dead_letter_with_retry(
                        stop_flag, metrics,
                        kafka_producer=dead_letter_producer, ch_client=ch_client, tenant_key=tenant_key,
                        component="correlator", source_location=source_location,
                        error="UnparseableEvent: permanently malformed field", raw_event=raw_line,
                    ):
                        result = None  # shutting down mid-retry - don't commit
                        break
                    consumer.commit(msg)
                    result = None
                    break
                except Exception as exc:  # noqa: BLE001 - presumed transient (e.g. database outage): retry forever, never dead-letter, never commit
                    db.close()
                    attempt_n += 1
                    metrics.incr("process_errors")
                    logger.warning(
                        "process_event attempt %d failed for alert %s (transient - retrying): %s",
                        attempt_n, event.alert_id, exc,
                    )
                    delay = min(PROCESS_BASE_DELAY_SECONDS * (2 ** (attempt_n - 1)), PROCESS_MAX_DELAY_SECONDS)
                    if stop_flag.wait(delay):
                        result = None  # graceful shutdown mid-retry: leave uncommitted, genuinely redelivered on restart
                        break
                    continue
                else:
                    db.close()
                    break

            if result is None:
                continue

            metrics.incr(f"alerts_{result.status}")
            consumer.commit(msg)
    finally:
        consumer.close()
