"""Kafka consumer group that batch-inserts normalised events into
ClickHouse, committing offsets only after the insert is confirmed.

Ordering that makes this safe:
  1. poll a batch of messages (no offset movement is durable yet - these
     are only "fetched", not committed)
  2. normalise each message; a message that fails to normalise is counted
     and dropped from the batch, not retried forever
  3. batch-insert the survivors into ClickHouse (one client.insert() call,
     never row by row)
  4. only on successful return from that insert, commit offsets

If the process dies between 3 and 4, the next consumer in the group
re-reads the same offset range on restart and re-inserts it - that's a
real duplicate at the ClickHouse layer. Two independent defenses against
that, not one (see PHASE3_DATA_PLATFORM.md's "Phase 3 follow-up 1" section
for the full writeup and the real, measured behavior of each):

- Step 3 inserts with `insert_deduplication_token` set from (topic,
  partition, offset) - confirmed this also protects the dependent
  materialized view (events_hourly_rollup_mv) even with
  deduplicate_blocks_in_dependent_materialized_views at its default (0).
  Phase 5.6 Item 3 follow-up found that deriving the token from
  "whatever got batched together" doesn't survive a replay at a
  different speed (proved: a slow write then a full-speed replay of the
  same 12 messages produced 24 rows) - a batch grouped by arrival timing
  can never be guaranteed to match a DIFFERENT run's grouping of the
  same offsets. See DEDUP_CHUNK_SIZE's own comment for the fix: bucket
  purely by offset, batch only a COMPLETE fixed-size bucket, fall back
  to one insert per row for whatever's incomplete (the tail, or a
  not-yet-full partition's entire backlog under low/moderate traffic).
- schema/events_schema.sql's events table (ReplicatedReplacingMergeTree,
  dedup on tenant_id/cluster_node/alert_id) and events_hourly_rollup
  (uniqExact on cluster_node/alert_id) are the backstop for whatever the
  token doesn't catch - they dedup by identity, not by batch shape, so
  they hold even when the token-based defense above doesn't apply.
"""

import logging
import time

import clickhouse_connect
from confluent_kafka import Consumer, Producer
from sqlalchemy import create_engine

from .dead_letter import send_to_dead_letter
from .metrics import Metrics
from .normalizer import normalize_alert
from .retry import retry_with_backoff, consumer_heartbeat
from .shipper import ENVELOPE_VERSION
from .tenants import TenantCache
from .topics import ALERTS_TOPIC_PATTERN, tenant_from_alerts_topic

INSERT_BASE_DELAY_SECONDS = 1.0
INSERT_MAX_DELAY_SECONDS = 30.0

logger = logging.getLogger(__name__)

BATCH_MAX_MESSAGES = 1000
BATCH_MAX_SECONDS = 2.0
POLL_TIMEOUT_SECONDS = 1.0
# Phase 5.6 Item 3 follow-up: idle-gap flush alone is NOT sufficient -
# proved for real (test_item3_followup_proof.py, now deleted after use):
# a range written slowly (gaps > BATCH_MAX_SECONDS, so idle-gap-flush
# fires after nearly every message) then replayed at full speed (a new
# consumer group reading the same, now fully-published backlog with no
# gaps at all) produced 24 raw rows for 12 real messages - the SLOW pass
# flushed ~12 tiny batches (tokens "offset N-N" each), the FAST pass
# flushed ~1 big batch (token "offset 0-11") - neither token set matches
# the other's, so ClickHouse's block-level dedup can't recognize the
# replay as already-seen data at all.
# Root cause: insert_deduplication_token is a per-INSERT-statement
# setting, matched only by an EXACT repeat of the same token string - it
# can never be made to match across two DIFFERENT groupings of the same
# rows, and grouping-by-arrival-timing can never be made identical
# across two runs at different speeds (a consumer has no way to tell "a
# slow but still-live stream" from "a stream that's permanently done"
# from timing alone).
# Fix: decouple "how we batch for insert efficiency" from "what the
# dedup token covers" - bucket every row by a FIXED, offset-only
# function (offset // DEDUP_CHUNK_SIZE), not by arrival time:
#   - a COMPLETE bucket (exactly DEDUP_CHUNK_SIZE consecutive offsets,
#     all captured in this flush) is batch-inserted as one call, token
#     = the bucket's own fixed range - this is deterministic regardless
#     of timing, since "the count reached a fixed number" never depends
#     on how fast or slow those messages arrived.
#   - an INCOMPLETE bucket (the tail of whatever's currently available,
#     or a slice split across flush boundaries) cannot be trusted to
#     group identically across two different-speed runs, so each of its
#     rows gets inserted individually, tokened by its own exact
#     (topic, partition, offset) - this is the one granularity ClickHouse
#     can always match on a replay, no matter how the rows get batched.
# Trade-off, accepted deliberately: low/moderate-throughput partitions
# (most real traffic, most of the time) mostly pay per-row inserts
# instead of one big batch - bounded by DEDUP_CHUNK_SIZE-1 extra calls
# per flush at worst, same worst case idle-gap-flush already had before
# this fix (every message its own tiny batch), just now provably
# correct instead of accidentally-usually-correct. A sustained burst
# (DEDUP_CHUNK_SIZE+ messages at once) still gets full batch efficiency.
DEDUP_CHUNK_SIZE = 100

COLUMNS = [
    "tenant_id", "time", "cluster_node", "manager_name", "alert_id",
    "agent_id", "agent_name", "agent_ip",
    "rule_id", "rule_level", "rule_description", "rule_groups",
    "mitre_ids", "mitre_tactics", "mitre_techniques",
    "src_endpoint_ip", "src_endpoint_port", "dst_endpoint_ip", "dst_endpoint_port",
    "actor_user", "target_user",
    "decoder_name", "location", "message", "extra_fields", "raw_event",
]


def _row(ev) -> list:
    return [getattr(ev, col) for col in COLUMNS]


class _FailoverClickHouse:
    """Tries each (host, port) candidate in order on insert, so losing one
    ClickHouse replica doesn't stop ingestion. Not a real load balancer -
    no health checking between batches, no least-conns, nothing clever -
    just "try the one we used last, then fall through the rest." Good
    enough for 2 replicas in the lab; a real deployment would put the
    writer behind the same thing its query layer uses.
    """

    def __init__(self, hosts: list[tuple[str, int]], user: str, password: str, database: str):
        self._hosts = hosts
        self._user = user
        self._password = password
        self._database = database
        self._preferred = 0

    def insert(self, table: str, rows: list, column_names: list, settings: dict | None = None) -> int:
        last_exc = None
        order = [self._preferred] + [i for i in range(len(self._hosts)) if i != self._preferred]
        for i in order:
            host, port = self._hosts[i]
            try:
                client = clickhouse_connect.get_client(
                    host=host, port=port, username=self._user,
                    password=self._password, database=self._database,
                )
                client.insert(table, rows, column_names=column_names, settings=settings)
                client.close()
                self._preferred = i
                return i
            except Exception as exc:  # noqa: BLE001 - genuinely any backend failure should fail over
                last_exc = exc
                continue
        raise last_exc


def run(
    bootstrap_servers: str,
    group_id: str,
    clickhouse_hosts: list[tuple[str, int]],
    clickhouse_user: str,
    clickhouse_password: str,
    clickhouse_database: str,
    database_url: str,
    metrics: Metrics,
    stop_flag,
    started_flag=None,
    kafka_client_config: dict | None = None,
):
    """Phase 5.6 Item 1: no single `topic` any more - every tenant has its
    own (topics.py), so this subscribes to ALERTS_TOPIC_PATTERN (a regex,
    not a literal name - the leading "^" is what tells confluent_kafka/
    librdkafka to treat it as one) and picks up every tenant's alerts
    topic at once, including ones created after this process started
    (bounded by topic.metadata.refresh.interval.ms).

    kafka_client_config carries whatever TLS/SASL settings this
    deployment needs (security.protocol, sasl.mechanism, sasl.username/
    password, ssl.ca.location, ...) - merged into both the Consumer and
    the dead-letter Producer's config, same credential either way since
    this component only ever needs one role's worth of ACLs."""
    kafka_client_config = kafka_client_config or {}
    consumer = Consumer({
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        # Phase 5.6 Item 1: librdkafka's default (300000ms/5min) is how
        # often a PATTERN subscription re-checks the broker's topic list
        # for new matches - confirmed for real (a brand-new tenant's
        # topic, created and immediately produced to, took anywhere from
        # ~27s to ~206s to even show up in this group's own `--describe`
        # output across repeated measurements, both well within that 5min
        # ceiling). 10s makes a brand-new tenant's first event land
        # promptly and consistently instead of depending on where in a
        # 5-minute window its topic happened to be created.
        "topic.metadata.refresh.interval.ms": 10000,
        **kafka_client_config,
    })
    consumer.subscribe([ALERTS_TOPIC_PATTERN])

    ch = _FailoverClickHouse(clickhouse_hosts, clickhouse_user, clickhouse_password, clickhouse_database)
    dead_letter_producer = Producer({"bootstrap.servers": bootstrap_servers, **kafka_client_config})
    # Phase 5C Step 0: a forged/stale/deleted tenant_key must never create
    # silent orphaned ClickHouse rows - see tenants.py's own docstring for
    # why this is a periodically-refreshed cache, not a query per message.
    tenant_cache = TenantCache(create_engine(database_url, pool_pre_ping=True))

    if started_flag is not None:
        started_flag.set()

    try:
        while not stop_flag.is_set():
            batch_msgs = []
            deadline = time.monotonic() + BATCH_MAX_SECONDS
            while len(batch_msgs) < BATCH_MAX_MESSAGES and time.monotonic() < deadline:
                msg = consumer.poll(POLL_TIMEOUT_SECONDS)
                if msg is None:
                    # Phase 5.6 Item 3: flush on a genuine idle gap once we
                    # already have something, instead of always waiting out
                    # the full BATCH_MAX_SECONDS regardless of arrival
                    # pattern. Root cause of a real flaky test
                    # (test_replay_does_not_inflate_base_table_or_rollup):
                    # insert_deduplication_token is derived from this
                    # batch's own offset range, so under load, a backlog
                    # that arrived as ONE batch on first consume could get
                    # split into TWO batches on replay purely because the
                    # fixed wall-clock deadline fired mid-stream - same
                    # offsets, different token, defeating block-level dedup
                    # (the ReplicatedReplacingMergeTree identity backstop
                    # still catches it, just not immediately - see the
                    # module docstring). A backlog that's fully available in
                    # Kafka returns messages back-to-back with no real idle
                    # gap, so this flushes early only when there's truly
                    # nothing more waiting, not because a clock ran out.
                    if batch_msgs:
                        break
                    continue
                if msg.error():
                    metrics.incr("messages_failed")
                    continue
                batch_msgs.append(msg)

            if not batch_msgs:
                continue

            # Deterministic batches: one insert per (topic, partition), each
            # with insert_deduplication_token derived from that partition's
            # exact offset range in this batch - see the module docstring.
            by_partition: dict[tuple[str, int], list] = {}
            for msg in batch_msgs:
                by_partition.setdefault((msg.topic(), msg.partition()), []).append(msg)

            for (msg_topic, partition), msgs in sorted(by_partition.items()):
                # Phase 5.6 Item 1: the TRUSTED identity is the topic this
                # message was actually read from - a per-tenant producer
                # ACL is what makes it trustworthy (docs/design/
                # KAFKA_AUTH.md), not the header below. Every message in
                # this group shares one topic, so this is computed once.
                # tenant_from_alerts_topic() returning None here would mean
                # a non-tenant topic matched ALERTS_TOPIC_PATTERN, which
                # can't happen if every topic this writer is subscribed to
                # was actually created via topics.alerts_topic_for_tenant -
                # loud enough to want a KeyError-shaped failure, not a
                # silent skip.
                topic_tenant = tenant_from_alerts_topic(msg_topic)
                rows = []
                for msg in msgs:
                    header_tenant_id = None
                    envelope_version_raw = None
                    for k, v in (msg.headers() or []):
                        if k == "tenant_id":
                            header_tenant_id = v.decode()
                        elif k == "envelope_version":
                            envelope_version_raw = v.decode()
                    # errors="replace", never strict: invalid UTF-8 bytes in
                    # a Kafka message value must not crash the writer the
                    # way a raw-mode file read once could (shipper.py) -
                    # replaced bytes fail JSON parsing naturally below and
                    # get dead-lettered there instead.
                    raw_line = msg.value().decode("utf-8", errors="replace")
                    # Phase 5.6 Item 1: a header that's PRESENT but
                    # disagrees with the topic it actually arrived on is
                    # the one thing a per-tenant ACL alone can't catch (a
                    # shipper can still write a false claim into its OWN
                    # tenant's topic) - dead-lettered, trusting the topic,
                    # never the header, for where this ships. A MISSING
                    # header (every message produced before this item, or
                    # any producer that just doesn't bother) makes no claim
                    # to disagree with, so it's not an error - same
                    # backward-compat stance Item 4 already took for a
                    # missing envelope_version header.
                    if header_tenant_id is not None and header_tenant_id != topic_tenant:
                        metrics.incr("messages_failed")
                        retry_with_backoff(
                            lambda: send_to_dead_letter(
                                kafka_producer=dead_letter_producer, ch_client=ch, tenant_key=topic_tenant,
                                component="writer", source_location=f"{msg_topic}:{partition}:{msg.offset()}",
                                error=f"tenant_topic_mismatch: topic claims {topic_tenant!r}, header claims {header_tenant_id!r}",
                                raw_event=raw_line, metrics=metrics,
                            ),
                            max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                            max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                            poll_fn=lambda: consumer_heartbeat(consumer),
                            on_retry=lambda attempt, exc2: logger.warning(
                                "dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc2,
                            ),
                        )
                        continue
                    # Phase 5.6 Item 4: a missing header predates this change
                    # (treated as version 1, the only shape that ever
                    # existed before it) - a PRESENT header this writer
                    # doesn't recognize is the real signal something newer
                    # produced it (e.g. a future 5C envelope change) and
                    # must not be silently misparsed the way the 46
                    # pre-envelope dead letters were (VERSIONING.md).
                    if envelope_version_raw is not None and envelope_version_raw != str(ENVELOPE_VERSION):
                        metrics.incr("messages_failed")
                        retry_with_backoff(
                            lambda: send_to_dead_letter(
                                kafka_producer=dead_letter_producer, ch_client=ch, tenant_key=topic_tenant,
                                component="writer", source_location=f"{msg_topic}:{partition}:{msg.offset()}",
                                error=f"unsupported_envelope_version: got {envelope_version_raw!r}, this writer only understands {ENVELOPE_VERSION}",
                                raw_event=raw_line, metrics=metrics,
                            ),
                            max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                            max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                            poll_fn=lambda: consumer_heartbeat(consumer),
                            on_retry=lambda attempt, exc2: logger.warning(
                                "dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc2,
                            ),
                        )
                        continue
                    # Phase 5C Step 0: a forged/stale/deleted tenant_key must
                    # never create silent orphaned ClickHouse rows - checked
                    # before normalize_alert, same permanent-bad-data path
                    # (never retried: this tenant_key isn't about to start
                    # existing mid-retry any more than a bad timestamp is).
                    # Phase 5.6 Item 1: checks topic_tenant now, not a
                    # header value - a topic only exists because its
                    # tenant was provisioned (create-kafka-topics.sh), so
                    # this now only ever fires for a tenant deleted AFTER
                    # its topic was created, not a forged claim (the
                    # mismatch check above already catches that).
                    if not tenant_cache.is_known(topic_tenant or ""):
                        metrics.incr("messages_failed")
                        retry_with_backoff(
                            lambda: send_to_dead_letter(
                                kafka_producer=dead_letter_producer, ch_client=ch, tenant_key=topic_tenant,
                                component="writer", source_location=f"{msg_topic}:{partition}:{msg.offset()}",
                                error="unknown_tenant", raw_event=raw_line, metrics=metrics,
                            ),
                            max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                            max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                            poll_fn=lambda: consumer_heartbeat(consumer),
                            on_retry=lambda attempt, exc2: logger.warning(
                                "dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc2,
                            ),
                        )
                        continue
                    try:
                        ev = normalize_alert(raw_line, topic_tenant or "")
                    except Exception as exc:  # noqa: BLE001 - any parse/normalize failure is permanent, never retried: dead-letter and move on
                        metrics.incr("messages_failed")
                        # The dead-letter call itself only ever raises for
                        # its Kafka-publish half (ClickHouse failures are
                        # caught inside it) - retried forever, same as any
                        # other transient infra failure, so this event is
                        # never silently lost with no durable record at all.
                        retry_with_backoff(
                            lambda: send_to_dead_letter(
                                kafka_producer=dead_letter_producer, ch_client=ch, tenant_key=topic_tenant,
                                component="writer", source_location=f"{msg_topic}:{partition}:{msg.offset()}",
                                error=f"{type(exc).__name__}: {exc}", raw_event=raw_line, metrics=metrics,
                            ),
                            max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                            max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                            poll_fn=lambda: consumer_heartbeat(consumer),
                            on_retry=lambda attempt, exc2: logger.warning(
                                "dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc2,
                            ),
                        )
                        continue
                    if ev.cluster_node_fell_back:
                        logger.warning(
                            "alert %s has no cluster.node, fell back to manager.name=%s",
                            ev.alert_id, ev.cluster_node,
                        )
                        metrics.incr("cluster_node_fallback_count")
                    rows.append((msg.offset(), _row(ev)))

                if not rows:
                    continue

                # Phase 5.6 Item 3 follow-up: bucket by a FIXED function of
                # offset alone (see DEDUP_CHUNK_SIZE's own comment) - never
                # by how these rows happened to be grouped by arrival timing.
                by_bucket: dict[int, list[tuple[int, list]]] = {}
                for offset, row in rows:
                    by_bucket.setdefault(offset // DEDUP_CHUNK_SIZE, []).append((offset, row))

                for bucket, bucket_items in sorted(by_bucket.items()):
                    # By the time a row gets here it already passed
                    # normalize_alert() - any insert failure now is presumed
                    # infrastructure (ClickHouse unreachable/overloaded), not
                    # bad data. Retry forever with capped backoff; never
                    # dead-letter this path. stop_flag lets a graceful
                    # shutdown interrupt a long wait instead of blocking it.
                    if len(bucket_items) == DEDUP_CHUNK_SIZE:
                        # A complete, offset-aligned bucket - safe to batch,
                        # token is the bucket's own fixed range.
                        bucket_rows = [row for _, row in bucket_items]
                        token = f"{msg_topic}:{partition}:chunk{bucket}"
                        retry_with_backoff(
                            lambda rows=bucket_rows, token=token: ch.insert(
                                "events", rows, column_names=COLUMNS, settings={"insert_deduplication_token": token},
                            ),
                            max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                            max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                            poll_fn=lambda: consumer_heartbeat(consumer),
                            on_retry=lambda attempt, exc: logger.warning(
                                "ClickHouse insert attempt %d failed (transient - retrying): %s", attempt, exc,
                            ),
                        )
                        metrics.incr("messages_inserted", len(bucket_rows))
                    else:
                        # An incomplete bucket (the tail of what's currently
                        # available, or a slice split across flush
                        # boundaries) - its grouping can't be trusted to
                        # match a replay at a different speed, so each row
                        # gets its own token instead of a batch-wide one.
                        for offset, row in bucket_items:
                            token = f"{msg_topic}:{partition}:{offset}"
                            retry_with_backoff(
                                lambda row=row, token=token: ch.insert(
                                    "events", [row], column_names=COLUMNS, settings={"insert_deduplication_token": token},
                                ),
                                max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                                max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                                poll_fn=lambda: consumer_heartbeat(consumer),
                                on_retry=lambda attempt, exc: logger.warning(
                                    "ClickHouse insert attempt %d failed (transient - retrying): %s", attempt, exc,
                                ),
                            )
                            metrics.incr("messages_inserted", 1)

            consumer.commit(asynchronous=False)
            metrics.incr("batches_committed")
    finally:
        consumer.close()
