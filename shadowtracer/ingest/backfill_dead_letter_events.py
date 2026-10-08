#!/usr/bin/env python3
"""Dead-letter-ClickHouse incident (2026-10-08) follow-up: backfills
dead_letter_events from the Kafka dead-letter topic, so a ClickHouse
outage that only degrades the queryable copy (see dead_letter.py's own
docstring - a ClickHouse-side failure there is caught and counted on
dead_letter_ch_failures, never dropped) doesn't leave a permanent hole in
it once ClickHouse is healthy again.

One-shot: drains the topic from this consumer group's last committed
offset through to the current end, inserts, exits. Safe to re-run any
number of times (e.g. the first run gets interrupted, or you're not sure
it finished) - doubly idempotent, same as writer.py's own events-table
inserts:
  - KAFKA_GROUP_ID's committed offsets mean a re-run only re-reads
    whatever wasn't committed last time, never the whole topic.
  - Even if the same offset range IS re-read (a crash between insert and
    commit), insert_deduplication_token keyed on (topic, partition,
    offset range) makes ClickHouse drop the duplicate INSERT at the block
    level - see writer.py's module docstring for why this isn't
    guaranteed for every possible replay, just a live one like this.

Usage: KAFKA_GROUP_ID=dead-letter-ch-backfill CLICKHOUSE_USER=... \\
  CLICKHOUSE_PASSWORD=... ./backfill_dead_letter_events.py

Env vars: same as run_writer.py (KAFKA_BOOTSTRAP_SERVERS, KAFKA_GROUP_ID,
CLICKHOUSE_HOSTS, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD,
CLICKHOUSE_DATABASE), plus DEAD_LETTER_TOPIC (defaults to
dead_letter.DEAD_LETTER_TOPIC).
"""

import datetime
import json
import logging
import os

from confluent_kafka import Consumer

from shadowtracer_ingest.dead_letter import DEAD_LETTER_TOPIC
from shadowtracer_ingest.retry import retry_with_backoff
from shadowtracer_ingest.writer import _FailoverClickHouse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

COLUMNS = [
    "tenant_id", "component", "source_location", "error",
    "raw_event_preview", "raw_event_size", "raw_event_sha256", "failed_at",
]
POLL_TIMEOUT_SECONDS = 2.0
# After this many consecutive empty polls, the topic is presumed drained
# up to its current end - a one-shot backfill, not a live consumer, so it
# exits rather than waiting forever for the next message that may never
# come.
CONSECUTIVE_EMPTY_POLLS_TO_STOP = 5


def _row_from_envelope(envelope: dict) -> list:
    failed_at = datetime.datetime.fromisoformat(envelope["failed_at"])
    return [
        envelope.get("tenant_key") or "", envelope["component"], envelope["source_location"],
        envelope["error"], envelope["raw_event_preview"], envelope["raw_event_size"],
        envelope["raw_event_sha256"], failed_at,
    ]


def backfill(consumer: Consumer, ch, topic: str) -> int:
    total_rows = 0
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

        batch = [msg]
        # Drain whatever else is already fetched without blocking, so a
        # backlog gets inserted in batches instead of one row at a time.
        while True:
            next_msg = consumer.poll(0)
            if next_msg is None or next_msg.error():
                break
            batch.append(next_msg)

        by_partition: dict[int, list] = {}
        for m in batch:
            by_partition.setdefault(m.partition(), []).append(m)

        for partition, msgs in sorted(by_partition.items()):
            rows = []
            for m in msgs:
                try:
                    envelope = json.loads(m.value().decode("utf-8"))
                    rows.append(_row_from_envelope(envelope))
                except Exception as exc:  # noqa: BLE001 - a malformed dead-letter envelope is itself permanent bad data; skip it rather than block the rest of the backfill on it
                    logger.warning(
                        "skipping unparseable dead-letter envelope at %s:%d:%d: %s",
                        topic, partition, m.offset(), exc,
                    )
            if not rows:
                continue

            offsets = [m.offset() for m in msgs]
            token = f"backfill:{topic}:{partition}:{min(offsets)}-{max(offsets)}"
            retry_with_backoff(
                lambda: ch.insert("dead_letter_events", rows, column_names=COLUMNS,
                                   settings={"insert_deduplication_token": token}),
                on_retry=lambda attempt, exc: logger.warning(
                    "ClickHouse insert attempt %d failed (retrying): %s", attempt, exc,
                ),
            )
            total_rows += len(rows)
            logger.info("backfilled %d row(s) from partition %d (offsets %d-%d)",
                        len(rows), partition, min(offsets), max(offsets))

        consumer.commit(asynchronous=False)

    return total_rows


def main():
    hosts_raw = os.environ.get("CLICKHOUSE_HOSTS", "127.0.0.1:8123,127.0.0.1:8124")
    clickhouse_hosts = [(h, int(p)) for h, p in (hp.split(":") for hp in hosts_raw.split(","))]
    ch = _FailoverClickHouse(
        clickhouse_hosts,
        os.environ["CLICKHOUSE_USER"], os.environ["CLICKHOUSE_PASSWORD"],
        os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"),
    )

    topic = os.environ.get("DEAD_LETTER_TOPIC", DEAD_LETTER_TOPIC)
    consumer = Consumer({
        "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
        "group.id": os.environ.get("KAFKA_GROUP_ID", "dead-letter-ch-backfill"),
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([topic])
    try:
        total = backfill(consumer, ch, topic)
    finally:
        consumer.close()

    logger.info("done: backfilled %d row(s) total", total)


if __name__ == "__main__":
    main()
