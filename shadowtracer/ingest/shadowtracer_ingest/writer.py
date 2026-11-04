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

- Step 3 is ONE insert per batch (up to BATCH_MAX_ROWS rows or
  BATCH_MAX_SECONDS), whatever topics/partitions the rows came from. Its
  insert_deduplication_token names the batch's offset ranges, so an exact
  retry of the same insert is dropped by ClickHouse - a fast path only:
  a replay that cuts the same range into different batches gets different
  tokens and is inserted again.
- That is safe because correctness never depended on the token alone:
  schema/events_schema.sql's events table (ReplicatedReplacingMergeTree
  ORDER BY tenant_id, time, cluster_node, alert_id) collapses duplicates of
  an alert on merge, events_hourly_rollup counts uniqExact(cluster_node,
  alert_id), and readers tolerate an unmerged duplicate (see
  docs/design/THROUGHPUT_FIXES.md 4a). Phase 5.6's offset-bucket scheme,
  which made replays re-form identical blocks at the cost of one insert per
  row for every incomplete 100-offset bucket, is gone: it capped the writer
  at ~100-120 rows/s (docs/THROUGHPUT_BASELINE.md).
"""

import hashlib
import logging
import time

import clickhouse_connect
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from sqlalchemy import create_engine

from .dead_letter import send_to_dead_letter
from .metrics import Metrics
from .normalizer import normalize_alert
from .retry import retry_with_backoff, consumer_heartbeat
from .retry_state import mark_stuck, clear_stuck
from .shipper import ENVELOPE_VERSION
from .tenants import TenantCache
from .topics import ALERTS_TOPIC_PATTERN, tenant_from_alerts_topic

INSERT_BASE_DELAY_SECONDS = 1.0
INSERT_MAX_DELAY_SECONDS = 30.0

logger = logging.getLogger(__name__)

# Starting values (docs/design/THROUGHPUT_FIXES.md 4a): big enough that a
# backlog drains in a few large parts, small enough that a quiet stream is
# still written within ~1 s plus the insert.
BATCH_MAX_ROWS = 5000
BATCH_MAX_SECONDS = 1.0
POLL_TIMEOUT_SECONDS = 1.0

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
    topic_pattern: str = ALERTS_TOPIC_PATTERN,
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
    # topic_pattern only ever narrows this in tests (their own topics, never the lab's).
    consumer.subscribe([topic_pattern])

    ch = _FailoverClickHouse(clickhouse_hosts, clickhouse_user, clickhouse_password, clickhouse_database)
    # Same tuning as the consumer above, same reason - confirmed for
    # real on the PRODUCER side too, separately: a dead-letter topic
    # that briefly didn't exist (deleted, then recreated moments later)
    # kept failing with TOPIC_AUTHORIZATION_FAILED on every retry for
    # several more minutes after recreation, even though a brand-new
    # Producer against the exact same topic worked immediately - this
    # producer's own cached "doesn't exist" metadata for that topic
    # wasn't due to refresh yet. Only a process restart (a fresh
    # Producer, no stale cache) cleared it before this fix.
    dead_letter_producer = Producer({
        "bootstrap.servers": bootstrap_servers,
        "topic.metadata.refresh.interval.ms": 10000,
        **kafka_client_config,
    })
    pg_engine = create_engine(database_url, pool_pre_ping=True)
    # Phase 5C Step 0: a forged/stale/deleted tenant_key must never create
    # silent orphaned ClickHouse rows - see tenants.py's own docstring for
    # why this is a periodically-refreshed cache, not a query per message.
    tenant_cache = TenantCache(pg_engine)
    # Phase 5.6 closeout item 3: console-backend's /health/detail reads
    # this directly - see retry_state.py's own docstring. One small
    # closure per retry kind (both log AND record the stuck-state row)
    # instead of duplicating both calls at each of the 6 call sites below.
    retry_component = f"writer:{group_id}"

    def _on_dead_letter_retry(attempt, exc, tenant):
        logger.warning("dead-letter Kafka publish attempt %d failed (transient - retrying): %s", attempt, exc)
        # tenant identifies the TARGET dead-letter topic - confirmed the
        # hard way this needed to be here: without it, a stuck retry's
        # only clue is a bare KafkaError with no topic name, which (in
        # a real incident chasing exactly this) took far longer to
        # diagnose than it should have.
        mark_stuck(pg_engine, retry_component, group_id, consumer.assignment(), f"dead_letter_publish tenant={tenant}: {exc}")

    def _on_insert_retry(attempt, exc, msg_topic):
        logger.warning("ClickHouse insert attempt %d failed (transient - retrying): %s", attempt, exc)
        mark_stuck(pg_engine, retry_component, group_id, consumer.assignment(), f"clickhouse_insert topic={msg_topic}: {exc}")

    # A freshly started process is not in a retry: drop any stuck row a
    # previous incarnation left behind, or /health/ready would keep failing
    # until this process happened to retry and recover on its own.
    clear_stuck(pg_engine, retry_component)

    if started_flag is not None:
        started_flag.set()

    try:
        while not stop_flag.is_set():
            batch_msgs = []
            deadline = time.monotonic() + BATCH_MAX_SECONDS
            while len(batch_msgs) < BATCH_MAX_ROWS and time.monotonic() < deadline:
                msg = consumer.poll(POLL_TIMEOUT_SECONDS)
                if msg is None:
                    # Idle gap: flush what we have now rather than waiting out the deadline.
                    if batch_msgs:
                        break
                    continue
                if msg.error():
                    metrics.incr("messages_failed")
                    continue
                batch_msgs.append(msg)

            if not batch_msgs:
                continue

            # Validation and dead-lettering stay per message; every surviving
            # row goes into ONE insert for the whole batch (module docstring).
            batch_rows = []
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
                            on_retry=lambda attempt, exc2: _on_dead_letter_retry(attempt, exc2, topic_tenant),
                        )
                        clear_stuck(pg_engine, retry_component)
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
                            on_retry=lambda attempt, exc2: _on_dead_letter_retry(attempt, exc2, topic_tenant),
                        )
                        clear_stuck(pg_engine, retry_component)
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
                            on_retry=lambda attempt, exc2: _on_dead_letter_retry(attempt, exc2, topic_tenant),
                        )
                        clear_stuck(pg_engine, retry_component)
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
                            on_retry=lambda attempt, exc2: _on_dead_letter_retry(attempt, exc2, topic_tenant),
                        )
                        clear_stuck(pg_engine, retry_component)
                        continue
                    if ev.cluster_node_fell_back:
                        logger.warning(
                            "alert %s has no cluster.node, fell back to manager.name=%s",
                            ev.alert_id, ev.cluster_node,
                        )
                        metrics.incr("cluster_node_fallback_count")
                    batch_rows.append(_row(ev))

            if batch_rows:
                ranges = ";".join(
                    f"{t}:{p}:{min(m.offset() for m in ms)}-{max(m.offset() for m in ms)}"
                    for (t, p), ms in sorted(by_partition.items())
                )
                token = "batch:" + hashlib.sha256(ranges.encode()).hexdigest()
                topics = ",".join(sorted({t for t, _ in by_partition}))
                retried = []
                # By the time a row gets here it already passed
                # normalize_alert() - any insert failure now is presumed
                # infrastructure (ClickHouse unreachable/overloaded), not bad
                # data. Retry forever with capped backoff; never dead-letter
                # this path. stop_flag lets a graceful shutdown interrupt it.
                retry_with_backoff(
                    lambda: ch.insert("events", batch_rows, column_names=COLUMNS,
                                      settings={"insert_deduplication_token": token}),
                    max_attempts=None, base_delay=INSERT_BASE_DELAY_SECONDS,
                    max_delay=INSERT_MAX_DELAY_SECONDS, stop_flag=stop_flag,
                    poll_fn=lambda: consumer_heartbeat(consumer),
                    on_retry=lambda attempt, exc2: (retried.append(1), _on_insert_retry(attempt, exc2, topics)),
                )
                if retried:
                    clear_stuck(pg_engine, retry_component)  # only a retried insert ever marked itself stuck
                metrics.incr("messages_inserted", len(batch_rows))
                metrics.incr("insert_batches")

            # Real incident (Phase 5.6 closeout): a partition revoked
            # between this batch's poll() calls and this commit() (the
            # topic got deleted mid-batch - confirmed via the PARTCNT
            # "partition count changed from 1 to 0" log line right
            # before this) leaves librdkafka with nothing locally
            # stored to commit for it, and commit() raises
            # _NO_OFFSET/"Local: No offset stored" rather than silently
            # skipping that one partition - uncaught, this crashed the
            # whole writer process every time an ephemeral topic (a
            # test's own, in this lab) disappeared mid-cycle. There is
            # genuinely nothing to commit for a partition that no
            # longer exists, so this is caught and skipped, never
            # re-raised; any OTHER commit failure still propagates.
            try:
                consumer.commit(asynchronous=False)
            except KafkaException as exc:
                if exc.args[0].code() != KafkaError._NO_OFFSET:
                    raise
                logger.warning("commit skipped (partition revoked mid-batch, nothing to commit): %s", exc)
            metrics.incr("batches_committed")
    finally:
        consumer.close()
