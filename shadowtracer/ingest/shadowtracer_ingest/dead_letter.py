"""No single event may stop the pipeline: shared by the shipper, the
writer, and (imported the same way as normalizer.py) the correlator.
Called only for a PERMANENTLY malformed event - one that will never parse
or process correctly no matter how many times it's retried (a bad
timestamp, missing required fields, invalid UTF-8, ...) - never for a
transient failure (a database or broker being briefly unreachable),
which each caller retries with backoff instead and never reaches this
module for.

Dual-write, synchronously, from whichever component detects the failure,
with an explicit durability ORDER - not two independent writes of equal
standing:

  1. The Kafka dead-letter topic FIRST - the durable record of what
     happened and where, for someone to inspect or replay. A failure
     here is treated as TRANSIENT (same as a database being briefly
     unreachable): this function re-raises it unchanged, and every
     caller retries the whole call with backoff, never committing the
     triggering message's offset in the meantime - a dead-lettered event
     with NO durable record anywhere would be silent data loss, which
     this project never accepts.
  2. ClickHouse's dead_letter_events table SECOND - the queryable
     per-tenant count /health/detail reads (a Kafka topic has no cheap
     "how many for tenant X" query, and in-process counters don't
     survive a restart or aggregate across replicas). A failure here is
     caught INSIDE this function and never propagates: the Kafka copy
     above is already durable, so losing the queryable copy is degraded
     observability, not data loss, and must never crash the caller or
     block the pipeline (found the hard way - a stuck ClickHouse replica
     once did exactly that to a one-off replay consumer). Logged, and
     counted on `metrics` (dead_letter_ch_failures) if given, so the
     degradation is itself observable rather than silent.

Found and fixed the hard way (see docs/PHASE3_DATA_PLATFORM.md's
dead-letter-ClickHouse-incident entry): before this split, a ClickHouse-side
failure here raised uncaught, same as a Kafka-side one - reintroducing
the exact "one bad event crashes the whole process" failure mode this
module exists to prevent, for the SECONDARY, best-effort sink specifically.
"""

import datetime
import hashlib
import json
import logging

from .topics import dead_letter_topic_for_tenant

logger = logging.getLogger(__name__)

# Stored (both sinks) as a CAPPED PREVIEW plus the full payload's real size
# and sha256 - never the full payload. Two reasons: a raw_event that's
# HERE because it was too large for Kafka's message.max.bytes (a
# hostile/edge-case 10MB full_log, say) must not be re-embedded at full
# size in the envelope this module itself produces to Kafka - that second
# produce() would fail the exact same way, recursively - and ClickHouse
# shouldn't be made to store and retain full attacker-controlled payloads
# indefinitely just because they failed to parse. The sha256 is what lets
# anyone who needs the original match it against a replayed/re-shipped
# copy; source_location plus the preview is normally enough to diagnose
# the failure without it.
MAX_RAW_EVENT_PREVIEW_BYTES = 4096


def _preview(encoded: bytes) -> str:
    if len(encoded) <= MAX_RAW_EVENT_PREVIEW_BYTES:
        return encoded.decode("utf-8", errors="replace")
    return encoded[:MAX_RAW_EVENT_PREVIEW_BYTES].decode("utf-8", errors="ignore") + f"...<truncated, {len(encoded)} bytes total>"


def send_to_dead_letter(
    *,
    kafka_producer,
    ch_client,
    tenant_key: str,
    component: str,
    source_location: str,
    error: str,
    raw_event: str,
    metrics=None,
) -> None:
    """One event: see send_batch_to_dead_letter."""
    send_batch_to_dead_letter(
        kafka_producer=kafka_producer, ch_client=ch_client, tenant_key=tenant_key, component=component,
        failures=[(source_location, error, raw_event)], metrics=metrics,
    )


def send_batch_to_dead_letter(
    *,
    kafka_producer,
    ch_client,
    tenant_key: str,
    component: str,
    failures: list[tuple[str, str, str]],
    metrics=None,
) -> None:
    """Dead-letters every (source_location, error, raw_event) of one tenant
    with ONE Kafka flush and ONE ClickHouse insert. Per event, a burst of
    malformed input (e.g. lines split by a second writer appending to
    alerts.json) cost a full producer flush plus a ClickHouse round trip
    each and held a shipper to ~25 lines/s (THROUGHPUT_BASELINE.md §13).

    Raises if the Kafka publish fails (caller must retry the whole call,
    not commit - a retry may duplicate envelopes in the topic, never lose
    one); never raises if only the ClickHouse insert fails (logged and
    counted on `metrics` as dead_letter_ch_failures if given, but swallowed).

    Exception: if the tenant's dead-letter topic no longer exists (the
    tenant was offboarded), the ClickHouse rows become the durable record -
    then a ClickHouse failure raises (caller retries) and success returns
    normally, counted as dead_letter_topic_missing."""
    if not failures:
        return
    failed_at = datetime.datetime.now(datetime.timezone.utc)
    tenant_key = tenant_key or ""
    # Phase 5.6 Item 1: per-tenant topic, not one shared
    # shadowtracer.events.dead-letter - every caller passes a tenant_key
    # derived from a per-tenant ACL'd topic (or, for the shipper, its own
    # configured tenant), so this is never actually "" in practice.
    dead_letter_topic = dead_letter_topic_for_tenant(tenant_key)
    rows = []
    for source_location, error, raw_event in failures:
        encoded = raw_event.encode("utf-8", errors="replace")
        rows.append([tenant_key, component, source_location, error, _preview(encoded), len(encoded),
                     hashlib.sha256(encoded).hexdigest(), failed_at])

    if kafka_producer is not None:
        # Durable record #1 - a failure here must propagate (see module
        # docstring): never caught here.
        #
        # produce()/flush() alone do NOT detect a broker-unreachable kind
        # of delivery failure - confirmed empirically: flush() returns 0
        # (queue drained) even when every message actually timed out
        # undelivered, because confluent_kafka only reports that via the
        # on_delivery callback, never as an exception from produce() or
        # flush() themselves. Without checking it, this function would
        # return normally - silently - for exactly the failure case the
        # retry-forever contract above exists to catch. produce() itself
        # can still raise synchronously too (BufferError: local queue
        # full; KafkaException: e.g. message too large - shouldn't happen
        # here since the envelope is already capped, but not assumed).
        delivery_error = []

        def _on_delivery(err, _msg):
            if err is not None:
                delivery_error.append(err)

        try:
            for t, c, loc, err, preview, size, sha, _ in rows:
                envelope = {
                    "tenant_key": t, "component": c, "source_location": loc, "error": err,
                    "raw_event_preview": preview, "raw_event_size": size, "raw_event_sha256": sha,
                    "failed_at": failed_at.isoformat(),
                }
                kafka_producer.produce(
                    dead_letter_topic, value=json.dumps(envelope).encode(),
                    headers=[("tenant_id", tenant_key.encode())], on_delivery=_on_delivery,
                )
            still_pending = kafka_producer.flush(5)
            if still_pending or delivery_error:
                raise RuntimeError(
                    f"dead-letter Kafka publish did not durably succeed: "
                    f"still_pending={still_pending} delivery_error={delivery_error[:1]}"
                )
        except Exception:
            # An offboarded tenant (docs/design/TENANCY.md): its dead-letter
            # topic is deleted, so this publish can never succeed, and
            # retrying it forever stalls every tenant on the caller's
            # partitions. Only when the topic is absent from the cluster's own
            # metadata (not on a broker hiccup) do the ClickHouse rows become
            # the durable record - required, so their failure propagates.
            if ch_client is None or not _topic_missing(kafka_producer, dead_letter_topic):
                raise
            # A publish that merely timed out is still queued in the producer;
            # drop it, or every later flush() would report it as pending.
            # Callers never have other messages queued here: the writer and
            # correlator use a dead-letter-only producer, and the shipper
            # dead-letters a batch before producing its good lines.
            kafka_producer.purge()
            kafka_producer.poll(0)
            for r in rows:
                r[3] = f"{r[3]} [dead-letter topic missing: tenant offboarded]"
            _insert_dead_letter_rows(ch_client, rows)
            logger.warning("dead-letter topic %s does not exist (tenant offboarded?) - %d event(s) recorded in "
                           "ClickHouse only: component=%s first=%s", dead_letter_topic, len(rows), component, rows[0][2])
            if metrics is not None:
                metrics.incr("dead_letter_topic_missing", len(rows))
            return

    if ch_client is not None:
        try:
            _insert_dead_letter_rows(ch_client, rows)
        except Exception as exc:  # noqa: BLE001 - best-effort secondary sink: the Kafka copy above is already durable, so this must never crash the caller or block the pipeline
            logger.warning(
                "dead-letter ClickHouse insert failed (Kafka dead-letter topic copy already durable) "
                "component=%s tenant=%s rows=%d: %s", component, tenant_key, len(rows), exc,
            )
            if metrics is not None:
                metrics.incr("dead_letter_ch_failures")


def _insert_dead_letter_rows(ch_client, rows) -> None:
    ch_client.insert(
        "dead_letter_events",
        rows,
        column_names=[
            "tenant_id", "component", "source_location", "error",
            "raw_event_preview", "raw_event_size", "raw_event_sha256", "failed_at",
        ],
    )


def _topic_missing(kafka_producer, topic: str) -> bool:
    """True only if the cluster's metadata positively lists no such topic.
    A metadata request that itself fails (broker down) raises, so the
    caller keeps treating the publish failure as transient."""
    return topic not in kafka_producer.list_topics(timeout=10).topics
