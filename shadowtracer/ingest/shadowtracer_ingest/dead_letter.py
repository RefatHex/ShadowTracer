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
import hashlib
import json

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
) -> None:
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
        kafka_producer.produce(
            DEAD_LETTER_TOPIC, value=json.dumps(envelope).encode(),
            headers=[("tenant_id", tenant_key.encode())],
        )
        kafka_producer.flush(5)

    if ch_client is not None:
        ch_client.insert(
            "dead_letter_events",
            [[tenant_key, component, source_location, error, raw_event_preview, raw_event_size, raw_event_sha256, failed_at]],
            column_names=[
                "tenant_id", "component", "source_location", "error",
                "raw_event_preview", "raw_event_size", "raw_event_sha256", "failed_at",
            ],
        )
