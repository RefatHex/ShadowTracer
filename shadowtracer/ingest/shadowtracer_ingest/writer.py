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
real duplicate at the ClickHouse layer, which is exactly what
schema/001_events.sql's ReplicatingMergeTree dedup on (tenant_id,
cluster_node, alert_id) is for. See shadowtracer/docs/PHASE3_DATA_PLATFORM.md.
"""

import logging
import time

import clickhouse_connect
from confluent_kafka import Consumer

from .metrics import Metrics
from .normalizer import normalize_alert

logger = logging.getLogger(__name__)

BATCH_MAX_MESSAGES = 1000
BATCH_MAX_SECONDS = 2.0
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

    def insert(self, table: str, rows: list, column_names: list) -> int:
        last_exc = None
        order = [self._preferred] + [i for i in range(len(self._hosts)) if i != self._preferred]
        for i in order:
            host, port = self._hosts[i]
            try:
                client = clickhouse_connect.get_client(
                    host=host, port=port, username=self._user,
                    password=self._password, database=self._database,
                )
                client.insert(table, rows, column_names=column_names)
                client.close()
                self._preferred = i
                return i
            except Exception as exc:  # noqa: BLE001 - genuinely any backend failure should fail over
                last_exc = exc
                continue
        raise last_exc


def run(
    bootstrap_servers: str,
    topic: str,
    group_id: str,
    clickhouse_hosts: list[tuple[str, int]],
    clickhouse_user: str,
    clickhouse_password: str,
    clickhouse_database: str,
    metrics: Metrics,
    stop_flag,
    started_flag=None,
):
    consumer = Consumer({
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([topic])

    ch = _FailoverClickHouse(clickhouse_hosts, clickhouse_user, clickhouse_password, clickhouse_database)

    if started_flag is not None:
        started_flag.set()

    try:
        while not stop_flag.is_set():
            batch_msgs = []
            deadline = time.monotonic() + BATCH_MAX_SECONDS
            while len(batch_msgs) < BATCH_MAX_MESSAGES and time.monotonic() < deadline:
                msg = consumer.poll(POLL_TIMEOUT_SECONDS)
                if msg is None:
                    continue
                if msg.error():
                    metrics.incr("messages_failed")
                    continue
                batch_msgs.append(msg)

            if not batch_msgs:
                continue

            rows = []
            for msg in batch_msgs:
                tenant_id = None
                for k, v in (msg.headers() or []):
                    if k == "tenant_id":
                        tenant_id = v.decode()
                        break
                try:
                    ev = normalize_alert(msg.value().decode(), tenant_id or "")
                except Exception:
                    metrics.incr("messages_failed")
                    continue
                if ev.cluster_node_fell_back:
                    logger.warning(
                        "alert %s has no cluster.node, fell back to manager.name=%s",
                        ev.alert_id, ev.cluster_node,
                    )
                    metrics.incr("cluster_node_fallback_count")
                rows.append(_row(ev))

            if rows:
                ch.insert("events", rows, column_names=COLUMNS)
                metrics.incr("messages_inserted", len(rows))

            consumer.commit(asynchronous=False)
            metrics.incr("batches_committed")
    finally:
        consumer.close()
