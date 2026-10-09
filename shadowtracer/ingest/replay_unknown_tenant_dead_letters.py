#!/usr/bin/env python3
"""Phase 5C Step 0 follow-up: replays dead-lettered error="unknown_tenant"
events back through the real pipeline (the raw events topic), once the
tenant they belong to genuinely exists - closing the gap documented in
tenants.py's own docstring (TenantCache only ever triggers a refresh on a
stale-cache miss, so a brand-new tenant's first events can land in
dead_letter_events before the cache ever notices the tenant is real).

One-shot: drains the dead-letter topic from this consumer group's last
committed offset, re-produces the ORIGINAL raw_event_preview onto the raw
topic (under the same tenant_id header) for every unknown_tenant envelope
whose tenant_key now exists in `tenants`, and exits. Safe to re-run:

- A tenant that's STILL unknown is never skipped-and-forgotten: this
  run's own offset commit for that partition stops just short of the
  FIRST still-unknown one, so a future run (once the tenant exists) sees
  it again. Everything AFTER it in the same partition still gets
  attempted this run, same as everything before it.
- Re-producing the SAME event twice (a redundant replay after the
  rollback above, or simply re-running this script manually) is safe
  downstream regardless: the events table and incident_alerts are both
  keyed on the alert's own stable identity (alert_id), never on where or
  how many times it was produced - see writer.py's and
  shadowtracer_correlate/consumer.py's own module docstrings.

Limitation: raw_event_preview is CAPPED at 4KB (dead_letter.py) - an
event whose raw_event_size exceeds the preview's own byte length was
truncated, and replaying the preview alone would re-ingest a corrupted
(truncated-JSON) event. Detected and skipped (counted separately,
committed past - not recoverable through this path at all, no matter how
long it waits).

Usage: KAFKA_GROUP_ID=replay-unknown-tenant POSTGRES_HOST=... \\
  APP_DB_PASSWORD=... ./replay_unknown_tenant_dead_letters.py

Env vars: same as run_writer.py (KAFKA_BOOTSTRAP_SERVERS, KAFKA_GROUP_ID),
KAFKA_TOPIC (the RAW topic to replay onto, defaults to
shadowtracer.events.raw), POSTGRES_HOST/POSTGRES_PORT/POSTGRES_DB/
APP_DB_PASSWORD (to read the current tenants table), and
DEAD_LETTER_TOPIC (defaults to dead_letter.DEAD_LETTER_TOPIC).
"""

import json
import logging
import os

from confluent_kafka import Consumer, Producer, TopicPartition
from sqlalchemy import create_engine, text

from shadowtracer_ingest.dead_letter import DEAD_LETTER_TOPIC

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

POLL_TIMEOUT_SECONDS = 2.0
CONSECUTIVE_EMPTY_POLLS_TO_STOP = 5


def known_tenants(database_url: str) -> set[str]:
    engine = create_engine(database_url)
    with engine.connect() as conn:
        return set(conn.execute(text("SELECT tenant_key FROM tenants")).scalars().all())


def replay(consumer: Consumer, producer: Producer, dead_letter_topic: str, raw_topic: str, tenants: set[str]) -> dict:
    """tenants is a snapshot taken once at startup - a tenant created
    WHILE this script runs won't be picked up until the next invocation;
    fine for a one-shot operator tool. Returns a stats dict."""
    stats = {"replayed": 0, "still_unknown": 0, "truncated": 0, "malformed": 0}
    # Per partition: the first offset this run must NOT commit past,
    # because its tenant is still unknown. Absent = nothing holding it back.
    hold_at: dict[int, int] = {}
    max_seen: dict[int, int] = {}

    empty_polls = 0
    while empty_polls < CONSECUTIVE_EMPTY_POLLS_TO_STOP:
        msg = consumer.poll(POLL_TIMEOUT_SECONDS)
        if msg is None:
            empty_polls += 1
            continue
        empty_polls = 0
        if msg.error():
            logger.warning("consumer error, skipping: %s", msg.error())
            continue

        partition, offset = msg.partition(), msg.offset()
        max_seen[partition] = offset

        try:
            envelope = json.loads(msg.value().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - a malformed dead-letter envelope is itself permanent bad data; count it and move past it, never block on it
            stats["malformed"] += 1
            logger.warning("skipping unparseable dead-letter envelope at %s:%d:%d: %s",
                            dead_letter_topic, partition, offset, exc)
            continue

        if envelope.get("error") != "unknown_tenant":
            continue  # not this script's concern

        tenant_key = envelope.get("tenant_key") or ""
        if tenant_key not in tenants:
            stats["still_unknown"] += 1
            hold_at.setdefault(partition, offset)
            continue

        preview = envelope.get("raw_event_preview", "")
        if envelope.get("raw_event_size", 0) > len(preview.encode("utf-8")):
            stats["truncated"] += 1
            logger.warning(
                "skipping truncated (unrecoverable) dead-letter envelope at %s:%d:%d for tenant %s - "
                "raw_event_size=%d > preview length %d",
                dead_letter_topic, partition, offset, tenant_key,
                envelope["raw_event_size"], len(preview.encode("utf-8")),
            )
            continue

        producer.produce(raw_topic, value=preview.encode("utf-8"), headers=[("tenant_id", tenant_key.encode())])
        stats["replayed"] += 1

    producer.flush(30)

    offsets_to_commit = [
        TopicPartition(dead_letter_topic, partition, hold_at.get(partition, last_offset + 1))
        for partition, last_offset in max_seen.items()
    ]
    if offsets_to_commit:
        consumer.commit(offsets=offsets_to_commit, asynchronous=False)

    return stats


def main():
    database_url = (
        f"postgresql+psycopg2://shadowtracer_app:{os.environ['APP_DB_PASSWORD']}"
        f"@{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:{os.environ.get('POSTGRES_PORT', '5432')}"
        f"/{os.environ.get('POSTGRES_DB', 'shadowtracer')}"
    )
    tenants = known_tenants(database_url)
    logger.info("%d known tenant(s) at startup", len(tenants))

    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094")
    raw_topic = os.environ.get("KAFKA_TOPIC", "shadowtracer.events.raw")
    dead_letter_topic = os.environ.get("DEAD_LETTER_TOPIC", DEAD_LETTER_TOPIC)

    consumer = Consumer({
        "bootstrap.servers": bootstrap,
        "group.id": os.environ.get("KAFKA_GROUP_ID", "replay-unknown-tenant"),
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([dead_letter_topic])
    producer = Producer({"bootstrap.servers": bootstrap})

    try:
        stats = replay(consumer, producer, dead_letter_topic, raw_topic, tenants)
    finally:
        consumer.close()

    logger.info("done: %s", stats)


if __name__ == "__main__":
    main()
