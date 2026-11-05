"""The correlation engine's Kafka consumer loop (Phase 5A Step 1): a
second, independent consumer group on the same raw events topic the
writer reads - never ClickHouse, which holds alert content but no
incident state. Messages are consumed in batches (BATCH_MAX_MESSAGES) and each batch is
one PostgreSQL transaction (correlator.process_batch - docs/design/
THROUGHPUT_FIXES.md 4b). Offsets are committed only after that transaction
has committed - if the process dies in between, the next consumer in the
group re-reads the batch on restart and reprocesses it, which process_batch
makes a safe no-op (see its own docstring).

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
from shadowtracer_ingest.dead_letter import send_batch_to_dead_letter  # noqa: E402
from shadowtracer_ingest.normalizer import normalize_alert  # noqa: E402
from shadowtracer_ingest.retry import consumer_heartbeat  # noqa: E402
from shadowtracer_ingest.retry_state import mark_stuck, clear_stuck  # noqa: E402
from shadowtracer_ingest.shipper import ENVELOPE_VERSION  # noqa: E402
from shadowtracer_ingest.tenants import TenantCache  # noqa: E402
from shadowtracer_ingest.topics import ALERTS_TOPIC_PATTERN, tenant_from_alerts_topic  # noqa: E402

from confluent_kafka import Consumer, Producer, TopicPartition
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .correlator import (
    DEFAULT_MAX_SPAN_SECONDS, DEFAULT_SESSION_GAP_SECONDS, UnparseableEvent,
    correlation_key_and_basis, parse_alert_time, process_batch,
)
from .sequences import DEFAULT_LATENESS_SECONDS
from .metrics import Metrics
from .profiling import BatchProfiler
from .sequences import load_sequences

logger = logging.getLogger(__name__)

POLL_TIMEOUT_SECONDS = 1.0
# docs/design/THROUGHPUT_FIXES.md 4b: one transaction per poll batch.
BATCH_MAX_MESSAGES = 500
PROCESS_BASE_DELAY_SECONDS = 1.0
PROCESS_MAX_DELAY_SECONDS = 30.0


def _wait_polling(stop_flag, delay, consumer) -> bool:
    """Waits up to delay seconds in <=1s steps, calling
    consumer_heartbeat(consumer) each step - keeps the consumer's group
    membership alive during a long backoff instead of one blocking
    wait (consumer_heartbeat pauses first so this can never silently
    dequeue-and-drop a real message the way a bare consumer.poll(0)
    could). A real incident: an unbroken wait here let a consumer
    exceed max.poll.interval.ms and fall out of its group, stalling
    every partition it owned (not just the one retry) until the
    process was restarted. Returns True if stop_flag fired (caller
    should give up)."""
    remaining = delay
    while remaining > 0:
        step = min(1.0, remaining)
        consumer_heartbeat(consumer)
        if stop_flag.wait(step):
            return True
        remaining -= step
    return False


def _dead_letter_with_retry(stop_flag, metrics, consumer, pg_engine, retry_component, group_id, **kwargs) -> bool:
    """Returns True once the dead-letter write succeeds durably (via the
    Kafka dead-letter topic - send_batch_to_dead_letter only ever raises for
    that half, since a ClickHouse-side failure is already caught inside
    it), retrying forever with backoff in between - same as any other
    transient infra failure, so a permanently bad event is never left
    with no durable record anywhere. Returns False only if stop_flag
    fires mid-retry (graceful shutdown) - the caller must NOT commit the
    triggering message's offset in that case, so it's genuinely
    redelivered and retried again after restart.

    pg_engine/component: Phase 5.6 closeout item 3 - console-backend's
    /health/detail reads component_retry_state directly (see
    retry_state.py's own docstring); mark_stuck/clear_stuck make this
    retry loop visible there the same way writer.py's does."""
    attempt = 0
    while True:
        try:
            send_batch_to_dead_letter(metrics=metrics, **kwargs)
            clear_stuck(pg_engine, retry_component)
            return True
        except Exception as exc:  # noqa: BLE001 - the Kafka publish itself failing is transient, not bad data
            attempt += 1
            logger.warning("dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc)
            # tenant_key identifies the TARGET dead-letter topic - see
            # writer.py's identical comment for why this matters.
            mark_stuck(pg_engine, retry_component, group_id, consumer.assignment(), f"dead_letter_publish tenant={kwargs.get('tenant_key')}: {exc}")
            delay = min(PROCESS_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), PROCESS_MAX_DELAY_SECONDS)
            if _wait_polling(stop_flag, delay, consumer):
                return False


def run(
    bootstrap_servers: str,
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
    kafka_client_config: dict | None = None,
    topic_pattern: str = ALERTS_TOPIC_PATTERN,
):
    """ch_client is optional (None is fine, e.g. in tests that don't care
    about dead-letter counts) - a dead-lettered event still always goes to
    the Kafka dead-letter topic either way; ch_client only adds the
    queryable-per-tenant-count side of send_to_dead_letter.

    Phase 5B Step 4: sequences_dir/clickhouse_database are optional too -
    omitted, sequence detection is simply not evaluated (ch_client alone
    isn't enough; see process_event's own docstring for why both are
    required together).

    Phase 5.6 Item 1: no `topic` parameter any more - subscribes to
    ALERTS_TOPIC_PATTERN (every tenant's own topic at once, see
    shadowtracer_ingest/topics.py and writer.py's identical change).
    kafka_client_config carries whatever TLS/SASL settings this
    deployment needs."""
    kafka_client_config = kafka_client_config or {}
    sequences = load_sequences(sequences_dir) if sequences_dir else None
    consumer = Consumer({
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        # Phase 5.6 Item 1: see writer.py's own identical comment - a
        # PATTERN subscription's new-topic discovery otherwise depends
        # on librdkafka's default 5-minute refresh interval.
        "topic.metadata.refresh.interval.ms": 10000,
        **kafka_client_config,
    })
    # topic_pattern only ever narrows this in tests (their own topics, never the lab's).
    consumer.subscribe([topic_pattern])

    engine = create_engine(database_url, pool_pre_ping=True)
    profiler = BatchProfiler(engine)  # no-op unless SHADOWTRACER_PROFILE_BATCHES=1
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    # Same tuning as the consumer above, same reason - confirmed for
    # real on the PRODUCER side too, separately (see writer.py's own
    # identical comment): a dead-letter topic that briefly didn't
    # exist kept failing TOPIC_AUTHORIZATION_FAILED on every retry for
    # minutes after recreation, even though a brand-new Producer
    # against the same topic worked immediately - this producer's own
    # cached "doesn't exist" metadata wasn't due to refresh yet.
    dead_letter_producer = Producer({
        "bootstrap.servers": bootstrap_servers,
        "topic.metadata.refresh.interval.ms": 10000,
        # Tenant topics are provisioned explicitly (create-kafka-topics.sh);
        # never recreate an offboarded tenant's dead-letter topic by publishing to it.
        "allow.auto.create.topics": False,
        **kafka_client_config,
    })
    # Phase 5C Step 0: a forged/stale/deleted tenant_key must never create
    # silent orphaned incidents - see tenants.py's own docstring for why
    # this is a periodically-refreshed cache, not a query per message.
    tenant_cache = TenantCache(engine)
    # Phase 5.6 closeout item 3: console-backend's /health/detail reads
    # this directly - see retry_state.py's own docstring.
    retry_component = f"correlator:{group_id}"

    # A freshly started process is not in a retry: drop any stuck row a
    # previous incarnation left behind, or /health/ready would keep failing
    # until this process happened to retry and recover on its own.
    clear_stuck(engine, retry_component)

    if started_flag is not None:
        started_flag.set()

    def dead_letter(tenant_key, failures) -> bool:
        return _dead_letter_with_retry(
            stop_flag, metrics, consumer, engine, retry_component, group_id,
            kafka_producer=dead_letter_producer, ch_client=ch_client, tenant_key=tenant_key,
            component="correlator", failures=failures,
        )

    try:
        while not stop_flag.is_set():
            profiler.start()
            msgs = consumer.consume(num_messages=BATCH_MAX_MESSAGES, timeout=POLL_TIMEOUT_SECONDS)
            if not msgs:
                continue
            profiler.mark("consume")

            # Per-message checks first. Permanent bad data is dead-lettered
            # here, never retried, and its offset is committed together with
            # the batch below - never before it, since committing offset N+1
            # also commits everything before N in that partition.
            good = []  # (msg, event)
            handled = []  # every message whose offset may be committed once the batch is done
            dead = {}  # tenant_key -> [(source_location, error, raw_line)], one dead-letter call each
            shutting_down = False
            for msg in msgs:
                if msg.error():
                    metrics.incr("messages_failed")
                    continue

                # Phase 5.6 Item 1: the TRUSTED identity is the topic this
                # message was actually read from, not the header below - a
                # per-tenant producer ACL is what makes it trustworthy
                # (docs/design/KAFKA_AUTH.md).
                tenant_key = tenant_from_alerts_topic(msg.topic())
                header_tenant_id = None
                envelope_version_raw = None
                for k, v in (msg.headers() or []):
                    if k == "tenant_id":  # header name predates tenant_key (Phase 4 follow-up 1); the VALUE is the tenant_key
                        header_tenant_id = v.decode()
                    elif k == "envelope_version":
                        envelope_version_raw = v.decode()
                # errors="replace", never strict: invalid UTF-8 must not crash
                # the loop - it fails JSON parsing below and is dead-lettered.
                raw_line = msg.value().decode("utf-8", errors="replace")

                # A header that's PRESENT but disagrees with the topic is the
                # one thing a per-tenant ACL alone can't catch (Phase 5.6
                # Item 1); a MISSING header makes no claim, so it's not an error.
                if header_tenant_id is not None and header_tenant_id != tenant_key:
                    error = f"tenant_topic_mismatch: topic claims {tenant_key!r}, header claims {header_tenant_id!r}"
                # A PRESENT envelope version this correlator doesn't know means
                # something newer produced it (Phase 5.6 Item 4, VERSIONING.md).
                elif envelope_version_raw is not None and envelope_version_raw != str(ENVELOPE_VERSION):
                    error = f"unsupported_envelope_version: got {envelope_version_raw!r}, this correlator only understands {ENVELOPE_VERSION}"
                # Phase 5C Step 0: a forged/stale/deleted tenant never creates incidents.
                elif not tenant_cache.is_known(tenant_key or ""):
                    error = "unknown_tenant"
                else:
                    error = None
                    try:
                        event = normalize_alert(raw_line, tenant_key or "")
                        if correlation_key_and_basis(event) is not None:
                            parse_alert_time(event)  # one bad timestamp is dead-lettered alone, never fails the batch
                    except UnparseableEvent:
                        logger.warning("alert in %s has a permanently malformed field - dead-lettering, not retrying",
                                       f"{msg.topic()}:{msg.partition()}:{msg.offset()}")
                        error = "UnparseableEvent: permanently malformed field"
                    except Exception as exc:  # noqa: BLE001 - permanent, bad data: dead-letter and move on, never retried
                        error = f"{type(exc).__name__}: {exc}"

                if error is not None:
                    metrics.incr("messages_failed")
                    dead.setdefault(tenant_key, []).append(
                        (f"{msg.topic()}:{msg.partition()}:{msg.offset()}", error, raw_line))
                else:
                    good.append((msg, event))
                handled.append(msg)

            for dl_tenant, failures in dead.items():
                if not dead_letter(dl_tenant, failures):
                    shutting_down = True  # graceful shutdown mid-retry: commit nothing, the batch is redelivered
                    break
            if shutting_down:
                continue
            profiler.mark("prepare")

            # The whole batch in one transaction, retried in place forever with
            # capped backoff for a transient failure (e.g. the database is
            # briefly unreachable) - never dead-lettered, it's known-good data,
            # and process_batch is idempotent on redelivery.
            results = []
            attempt_n = 0
            while good:
                db = Session()
                try:
                    results = process_batch(
                        db, [ev for _, ev in good], session_gap_seconds, max_span_seconds,
                        sequences=sequences, ch_client=ch_client, clickhouse_database=clickhouse_database,
                        sequence_lateness_seconds=sequence_lateness_seconds, metrics=metrics,
                    )
                    break
                except Exception as exc:  # noqa: BLE001 - presumed transient: retry forever, never dead-letter, never commit
                    attempt_n += 1
                    metrics.incr("process_errors")
                    logger.warning("process_batch attempt %d failed for %d alerts (transient - retrying): %s",
                                   attempt_n, len(good), exc)
                    delay = min(PROCESS_BASE_DELAY_SECONDS * (2 ** (attempt_n - 1)), PROCESS_MAX_DELAY_SECONDS)
                    if _wait_polling(stop_flag, delay, consumer):
                        shutting_down = True  # graceful shutdown mid-retry: leave uncommitted, redelivered on restart
                        break
                finally:
                    db.close()
            if shutting_down:
                continue
            profiler.mark("process")

            for result in results:
                metrics.incr(f"alerts_{result.status}")
            offsets = {}
            for msg in handled:
                tp = (msg.topic(), msg.partition())
                offsets[tp] = max(offsets.get(tp, -1), msg.offset())
            # Asynchronous, like the per-message commits before: a commit lost to a
            # rebalance only means a redelivery, which process_batch makes a no-op.
            consumer.commit(offsets=[TopicPartition(t, p, o + 1) for (t, p), o in offsets.items()])
            profiler.mark("commit")
            profiler.emit(len(msgs), len(good))
            metrics.incr("batches_committed")
    finally:
        consumer.close()
