"""Tails a Wazuh manager's alerts.json (and archives.json, if raw events
are enabled for the tenant) and produces each line to Kafka.

One shipper process runs per manager node (Step 3). Design choices, and
why:

- Offset persistence is (inode, byte offset) per file, not just a byte
  offset - a log rotation that replaces the file at the same path gets a
  new inode, and resuming at the old byte offset against the new file
  would skip or misread data.
- The offset is advanced only after a batch is produced AND
  producer.flush() confirms every message in it was acked (acks=all).
  flush() blocks until that happens or raises on failure, so there is no
  window where we've advanced the offset for a message Kafka hasn't
  actually durably accepted yet.
  ponytail: flush()-per-batch is synchronous and caps throughput at
  batch-latency, not line-rate. A higher-throughput version would track
  per-message delivery callbacks against a sliding window of outstanding
  offsets instead of blocking the whole batch - add that if lab/prod
  throughput tests show this is the bottleneck.
- A line that isn't valid enough to extract an agent id from (malformed)
  is skipped with a counted warning, never raises past the read loop.
"""

import json
import os
import time

from confluent_kafka import KafkaException, Producer

from .dead_letter import send_to_dead_letter
from .metrics import Metrics

BATCH_MAX_LINES = 500
BATCH_MAX_SECONDS = 1.0
POLL_IDLE_SECONDS = 0.5


def load_offsets(offset_file: str) -> dict:
    if not os.path.exists(offset_file):
        return {}
    with open(offset_file, "r") as f:
        return json.load(f)


def save_offsets(offset_file: str, offsets: dict) -> None:
    tmp = offset_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump(offsets, f)
    os.replace(tmp, offset_file)  # atomic on the same filesystem


class TailSource:
    """Tails one file by (inode, offset), surviving rotation."""

    def __init__(self, path: str, state: dict):
        self.path = path
        self.inode = state.get("inode")
        self.offset = state.get("offset", 0)
        self._fd = None
        self._open_if_possible()

    def _open_if_possible(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        if self._fd is None:
            # Binary, not text mode - a text-mode file object raises
            # UnicodeDecodeError straight out of readline() on invalid
            # UTF-8 bytes, which would crash this generator (and the
            # whole shipper loop) on the very first bad byte instead of
            # dead-lettering just that one line and reading on past it.
            self._fd = open(self.path, "rb")
            if self.inode == st.st_ino:
                self._fd.seek(self.offset)
            else:
                # New file at this path (first run, or rotated since we
                # last saw it) - start from the beginning.
                self.inode = st.st_ino
                self.offset = 0

    def read_lines(self, max_lines: int):
        """Yields (line, byte_offset_after_line). Detects rotation by
        comparing the path's current inode to the one we're reading."""
        self._open_if_possible()
        if self._fd is None:
            return
        count = 0
        while count < max_lines:
            pos_before = self._fd.tell()
            raw_line = self._fd.readline()
            if not raw_line:
                break
            if not raw_line.endswith(b"\n"):
                # Partial line at EOF (writer hasn't finished it yet) -
                # rewind and wait for more.
                self._fd.seek(pos_before)
                break
            self.offset = self._fd.tell()
            # errors="replace", never strict: invalid UTF-8 bytes become
            # U+FFFD rather than raising here - the resulting (now valid
            # Python str) line fails JSON parsing naturally downstream
            # and gets dead-lettered there, instead of one bad byte
            # anywhere in the file stopping every line behind it from
            # ever being read at all.
            line = raw_line.rstrip(b"\n").decode("utf-8", errors="replace")
            yield line, self.offset
            count += 1

        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        if st.st_ino != self.inode:
            # Rotated: drain whatever's left of the old fd (already done
            # above since it hit EOF), then switch to the new file.
            self._fd.close()
            self._fd = None
            self.inode = None
            self.offset = 0

    def state(self) -> dict:
        return {"inode": self.inode, "offset": self.offset}


def extract_agent_id(line: str) -> str:
    """Just enough parsing to build the Kafka key - full parsing happens
    in the normaliser, in the writer. Raises on anything not even
    JSON-shaped; caller counts and skips."""
    alert = json.loads(line)
    return alert.get("agent", {}).get("id", "")


def run(
    tenant_id: str,
    manager_name: str,
    alerts_path: str,
    archives_path: str | None,
    bootstrap_servers: str,
    topic: str,
    offset_file: str,
    metrics: Metrics,
    stop_flag,
    ch_client=None,
):
    """ch_client is optional (None is fine, e.g. in tests that don't care
    about dead-letter counts) - a malformed line still always goes to the
    Kafka dead-letter topic either way; ch_client only adds the
    queryable-per-tenant-count side of send_to_dead_letter."""
    offsets = load_offsets(offset_file)
    sources = {"alerts.json": TailSource(alerts_path, offsets.get("alerts.json", {}))}
    if archives_path:
        sources["archives.json"] = TailSource(archives_path, offsets.get("archives.json", {}))

    producer = Producer({
        "bootstrap.servers": bootstrap_servers,
        "acks": "all",
        # Default (5 min) is too close to a real broker outage to be safe -
        # a message produced right before an outage could hit this timeout
        # mid-outage and be reported as failed before Kafka ever comes
        # back, even though it would have delivered fine. 20 min gives a
        # real margin over the kind of broker restart/maintenance window
        # this shipper needs to ride out.
        "message.timeout.ms": 1200000,
    })
    delivery_errors = []

    def on_delivery(err, msg):
        if err is not None:
            delivery_errors.append(err)

    while not stop_flag.is_set():
        did_work = False
        for source_name, source in sources.items():
            batch = []
            deadline = time.monotonic() + BATCH_MAX_SECONDS
            for line, byte_offset in source.read_lines(BATCH_MAX_LINES):
                batch.append((line, byte_offset))
                metrics.incr("lines_read")
                if time.monotonic() > deadline:
                    break
            if not batch:
                continue
            did_work = True

            delivery_errors.clear()
            for line, byte_offset in batch:
                try:
                    agent_id = extract_agent_id(line)
                except Exception as exc:  # noqa: BLE001 - any parse failure is permanent, never retried: dead-letter and move on (deeply nested JSON, invalid UTF-8, wrong types, ... none of these succeed on a retry)
                    metrics.incr("lines_failed")
                    send_to_dead_letter(
                        kafka_producer=producer, ch_client=ch_client, tenant_key=tenant_id,
                        component="shipper", source_location=f"{source.path}:{byte_offset}",
                        error=f"{type(exc).__name__}: {exc}", raw_event=line,
                    )
                    continue
                key = f"{tenant_id}:{agent_id}".encode()
                value = line.encode()
                headers = [
                    ("tenant_id", tenant_id.encode()),
                    ("source_manager", manager_name.encode()),
                    ("source_file", source_name.encode()),
                ]
                while True:
                    try:
                        producer.produce(topic, key=key, value=value, headers=headers, on_delivery=on_delivery)
                        break
                    except BufferError:
                        # Local produce queue full - transient backpressure,
                        # not bad data: drain some deliveries and retry the
                        # SAME message rather than dropping it.
                        producer.poll(1.0)
                        continue
                    except KafkaException as exc:
                        # e.g. message too large for the broker
                        # (message.max.bytes) - a hostile/edge-case huge
                        # full_log. Permanent: this exact message will
                        # never fit no matter how many times it's retried.
                        metrics.incr("lines_failed")
                        send_to_dead_letter(
                            kafka_producer=producer, ch_client=ch_client, tenant_key=tenant_id,
                            component="shipper", source_location=f"{source.path}:{byte_offset}",
                            error=f"{type(exc).__name__}: {exc}", raw_event=line,
                        )
                        break

            still_pending = producer.flush(30)

            # flush()'s return value is the count of messages still
            # outstanding after the timeout - during a broker outage,
            # confluent_kafka won't invoke on_delivery with an error until
            # message.timeout.ms elapses (default 5 minutes), so a 30s
            # flush() timeout during a longer outage leaves delivery_errors
            # empty even though nothing was actually acked. Checking only
            # delivery_errors here would have advanced the offset past
            # unacknowledged messages - exactly the loss this shipper
            # exists to prevent. Found running the Step 6 Kafka-outage test.
            if delivery_errors or still_pending:
                # Don't advance the offset - we'll re-read and retry this
                # batch next loop. Duplicates from a retried batch are
                # handled at the ClickHouse layer (see schema/events_schema.sql).
                metrics.incr("lines_failed", len(delivery_errors))
                continue

            metrics.incr("lines_sent", len(batch))
            offsets[source_name] = source.state()
            save_offsets(offset_file, offsets)
            metrics.set(f"lag_bytes_{source_name}", _current_lag(source))

        if not did_work:
            time.sleep(POLL_IDLE_SECONDS)


def _current_lag(source: TailSource) -> int:
    try:
        return max(0, os.stat(source.path).st_size - source.offset)
    except FileNotFoundError:
        return 0
