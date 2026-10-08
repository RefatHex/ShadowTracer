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

logger = logging.getLogger(__name__)

DEAD_LETTER_TOPIC = "shadowtracer.events.dead-letter"

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
    """Raises if the Kafka publish fails (caller must retry, not commit);
    never raises if only the ClickHouse insert fails (logged and counted
    on `metrics` as dead_letter_ch_failures if given, but swallowed)."""
    failed_at = datetime.datetime.now(datetime.timezone.utc)
    tenant_key = tenant_key or ""
    encoded = raw_event.encode("utf-8", errors="replace")
    raw_event_size = len(encoded)
    raw_event_sha256 = hashlib.sha256(encoded).hexdigest()
    raw_event_preview = _preview(encoded)

    if kafka_producer is not None:
        envelope = {
            "tenant_key": tenant_key, "component": component, "source_location": source_location,
            "error": error, "raw_event_preview": raw_event_preview, "raw_event_size": raw_event_size,
            "raw_event_sha256": raw_event_sha256, "failed_at": failed_at.isoformat(),
        }
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

        kafka_producer.produce(
            DEAD_LETTER_TOPIC, value=json.dumps(envelope).encode(),
            headers=[("tenant_id", tenant_key.encode())], on_delivery=_on_delivery,
        )
        still_pending = kafka_producer.flush(5)
        if still_pending or delivery_error:
            raise RuntimeError(
                f"dead-letter Kafka publish did not durably succeed: "
                f"still_pending={still_pending} delivery_error={delivery_error[:1]}"
            )

    if ch_client is not None:
        try:
            ch_client.insert(
                "dead_letter_events",
                [[tenant_key, component, source_location, error, raw_event_preview, raw_event_size, raw_event_sha256, failed_at]],
                column_names=[
                    "tenant_id", "component", "source_location", "error",
                    "raw_event_preview", "raw_event_size", "raw_event_sha256", "failed_at",
                ],
            )
        except Exception as exc:  # noqa: BLE001 - best-effort secondary sink: the Kafka copy above is already durable, so this must never crash the caller or block the pipeline
            logger.warning(
                "dead-letter ClickHouse insert failed (Kafka dead-letter topic copy already durable) "
                "component=%s tenant=%s: %s", component, tenant_key, exc,
            )
            if metrics is not None:
                metrics.incr("dead_letter_ch_failures")
