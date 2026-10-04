"""No single event may stop the pipeline: shared by the shipper, the
writer, and (imported the same way as normalizer.py) the correlator.
Called only for a PERMANENTLY malformed event - one that will never parse
or process correctly no matter how many times it's retried (a bad
timestamp, missing required fields, invalid UTF-8, ...) - never for a
transient failure (a database or broker being briefly unreachable),
which each caller retries with backoff instead and never reaches this
module for.

Dual-write, synchronously, from whichever component detects the failure:
the Kafka dead-letter topic (the durable record of what happened and
where, for someone to inspect or replay) and ClickHouse's
dead_letter_events table (the queryable per-tenant count /health/detail
reads - a Kafka topic has no cheap "how many for tenant X" query, and
in-process counters don't survive a restart or aggregate across
replicas).
"""

import datetime
import json

DEAD_LETTER_TOPIC = "shadowtracer.events.dead-letter"

# A raw_event that's HERE because it was too large for Kafka's
# message.max.bytes (a hostile/edge-case 10MB full_log, say) must not be
# re-embedded at full size in the envelope this module itself produces to
# Kafka - that second produce() would fail the exact same way, recursively.
# Truncating keeps the dead-letter record itself well under the broker's
# default limit; source_location still points at where to find the
# original if it's ever needed.
MAX_RAW_EVENT_BYTES = 65536


def _truncate(raw_event: str) -> str:
    encoded = raw_event.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_RAW_EVENT_BYTES:
        return raw_event
    return encoded[:MAX_RAW_EVENT_BYTES].decode("utf-8", errors="ignore") + f"...<truncated, {len(encoded)} bytes total>"


def send_to_dead_letter(
    *,
    kafka_producer,
    ch_client,
    tenant_key: str,
    component: str,
    source_location: str,
    error: str,
    raw_event: str,
) -> None:
    failed_at = datetime.datetime.now(datetime.timezone.utc)
    tenant_key = tenant_key or ""
    raw_event = _truncate(raw_event)

    if kafka_producer is not None:
        envelope = {
            "tenant_key": tenant_key, "component": component, "source_location": source_location,
            "error": error, "raw_event": raw_event, "failed_at": failed_at.isoformat(),
        }
        kafka_producer.produce(
            DEAD_LETTER_TOPIC, value=json.dumps(envelope).encode(),
            headers=[("tenant_id", tenant_key.encode())],
        )
        kafka_producer.flush(5)

    if ch_client is not None:
        ch_client.insert(
            "dead_letter_events",
            [[tenant_key, component, source_location, error, raw_event, failed_at]],
            column_names=["tenant_id", "component", "source_location", "error", "raw_event", "failed_at"],
        )
