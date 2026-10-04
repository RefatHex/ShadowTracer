import json
import os
import threading
import time
import uuid

from confluent_kafka import Consumer

from shadowtracer_ingest import shipper
from shadowtracer_ingest.metrics import Metrics


def _drain_topic(kafka_bootstrap, topic, expected_count, timeout=15):
    """Always a fresh consumer group, so each call reads every message
    produced to the topic so far from the beginning - a prior call's
    auto-committed offsets must never make a later call see fewer messages."""
    consumer = Consumer({
        "bootstrap.servers": kafka_bootstrap,
        "group.id": f"test-drain-{topic}-{uuid.uuid4().hex[:8]}",
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([topic])
    messages = []
    deadline = time.monotonic() + timeout
    while len(messages) < expected_count and time.monotonic() < deadline:
        msg = consumer.poll(1.0)
        if msg is not None and msg.error() is None:
            messages.append(msg)
    consumer.close()
    return messages


def _run_shipper_once(tmp_path, kafka_bootstrap, topic, alerts_path, offset_file):
    metrics = Metrics()
    stop_flag = threading.Event()
    thread = threading.Thread(
        target=shipper.run,
        kwargs=dict(
            tenant_id="lab",
            manager_name="test-manager",
            alerts_path=str(alerts_path),
            archives_path=None,
            bootstrap_servers=kafka_bootstrap,
            topic=topic,
            offset_file=str(offset_file),
            metrics=metrics,
            stop_flag=stop_flag,
        ),
        daemon=True,
    )
    thread.start()
    return stop_flag, thread, metrics


def test_shipper_is_actually_running_and_draining_not_just_callable(tmp_path, kafka_bootstrap, kafka_topic, real_alert_lines):
    """Proves the shipper's main loop is live: we only start shipper.run()
    in a thread and write to the file it tails - never call its internal
    functions directly - then confirm messages actually arrive in Kafka."""
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text("\n".join(real_alert_lines) + "\n")
    offset_file = tmp_path / "offsets.json"

    stop_flag, thread, metrics = _run_shipper_once(tmp_path, kafka_bootstrap, kafka_topic, alerts_path, offset_file)
    messages = _drain_topic(kafka_bootstrap, kafka_topic, len(real_alert_lines))
    stop_flag.set()
    thread.join(timeout=5)

    assert len(messages) == len(real_alert_lines)
    keys = {m.key().decode() for m in messages}
    assert all(k.startswith("lab:") for k in keys)
    assert metrics.snapshot()["lines_sent"] == len(real_alert_lines)


def test_shipper_skips_malformed_lines_without_crashing(tmp_path, kafka_bootstrap, kafka_topic, real_alert_lines):
    alerts_path = tmp_path / "alerts.json"
    lines = [real_alert_lines[0], "{not valid json", real_alert_lines[1]]
    alerts_path.write_text("\n".join(lines) + "\n")
    offset_file = tmp_path / "offsets.json"

    stop_flag, thread, metrics = _run_shipper_once(tmp_path, kafka_bootstrap, kafka_topic, alerts_path, offset_file)
    messages = _drain_topic(kafka_bootstrap, kafka_topic, 2)
    stop_flag.set()
    thread.join(timeout=5)

    assert len(messages) == 2
    assert metrics.snapshot()["lines_failed"] >= 1


def test_shipper_dead_letters_bad_data_never_crashes(tmp_path, kafka_bootstrap, kafka_topic, ch_client, real_alert_lines):
    """No single event may stop the pipeline: a batch mixing permanently
    bad data (unparseable JSON, invalid UTF-8) with good lines must land
    every good line in Kafka, dead-letter every bad one (both to the Kafka
    dead-letter topic and ClickHouse's per-tenant-queryable table), and
    never crash the shipper thread."""
    marker = uuid.uuid4().hex[:8]
    alerts_path = tmp_path / "alerts.json"
    bad_lines_bytes = [
        b"{not valid json",
        # Invalid UTF-8 bytes outside any string quoting: errors="replace"
        # turns them into U+FFFD rather than crashing the read loop, but
        # the result is still not valid JSON (replacement chars aren't a
        # legal JSON value), so it fails downstream and gets dead-lettered
        # same as any other malformed line.
        b'\xff\xfe{"bad": "test"}',
    ]
    with open(alerts_path, "wb") as f:
        f.write(real_alert_lines[0].encode() + b"\n")
        for bad in bad_lines_bytes:
            f.write(bad + b"\n")
        f.write(real_alert_lines[1].encode() + b"\n")
    offset_file = tmp_path / "offsets.json"

    metrics = Metrics()
    stop_flag = threading.Event()
    thread = threading.Thread(
        target=shipper.run,
        kwargs=dict(
            tenant_id=f"test-{marker}", manager_name="test-manager", alerts_path=str(alerts_path),
            archives_path=None, bootstrap_servers=kafka_bootstrap, topic=kafka_topic,
            offset_file=str(offset_file), metrics=metrics, stop_flag=stop_flag, ch_client=ch_client,
        ),
        daemon=True,
    )
    thread.start()
    try:
        messages = _drain_topic(kafka_bootstrap, kafka_topic, 2)
        assert len(messages) == 2, "both good lines must still land in Kafka"

        deadline = time.monotonic() + 15
        dl_count = 0
        while time.monotonic() < deadline:
            dl_count = dl_client_count(ch_client, f"test-{marker}")
            if dl_count >= len(bad_lines_bytes):
                break
            time.sleep(0.5)
        assert dl_count == len(bad_lines_bytes), f"expected {len(bad_lines_bytes)} dead-lettered rows, got {dl_count}"
        assert thread.is_alive(), "shipper must never crash on bad data"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = 'test-{marker}'")


def dl_client_count(ch_client, tenant_id):
    return ch_client.query(
        f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant_id}' AND component = 'shipper'"
    ).result_rows[0][0]


def test_shipper_dead_letters_an_oversized_message_instead_of_crashing(
    tmp_path, kafka_bootstrap, kafka_topic, ch_client, real_alert_lines,
):
    """A message too large for Kafka's message.max.bytes (a hostile/edge
    case 10MB full_log) used to crash the shipper outright: producer.produce()
    raises KafkaException synchronously for this, uncaught, which would take
    down the whole process (and the container would restart) over a single
    bad line. Must dead-letter it and keep shipping everything else instead -
    and the oversized raw_event itself must not blow up the dead-letter
    envelope the same way (dead_letter.py truncates it)."""
    marker = uuid.uuid4().hex[:8]
    tenant_id = f"test-{marker}"
    good = json.loads(real_alert_lines[0])
    good["id"] = f"{good['id']}.{marker}"
    huge = json.loads(real_alert_lines[1])
    huge["id"] = f"{huge['id']}.{marker}.huge"
    huge["full_log"] = "x" * (11 * 1024 * 1024)

    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text(json.dumps(huge) + "\n" + json.dumps(good) + "\n")
    offset_file = tmp_path / "offsets.json"

    metrics = Metrics()
    stop_flag = threading.Event()
    thread = threading.Thread(
        target=shipper.run,
        kwargs=dict(
            tenant_id=tenant_id, manager_name="test-manager", alerts_path=str(alerts_path),
            archives_path=None, bootstrap_servers=kafka_bootstrap, topic=kafka_topic,
            offset_file=str(offset_file), metrics=metrics, stop_flag=stop_flag, ch_client=ch_client,
        ),
        daemon=True,
    )
    thread.start()
    try:
        messages = _drain_topic(kafka_bootstrap, kafka_topic, 1)
        assert len(messages) == 1, "the good line must still land in Kafka despite the oversized one"

        deadline = time.monotonic() + 15
        dl_count = 0
        while time.monotonic() < deadline:
            dl_count = dl_client_count(ch_client, tenant_id)
            if dl_count == 1:
                break
            time.sleep(0.5)
        assert dl_count == 1, "the oversized message must be dead-lettered, not silently dropped or crash the shipper"
        assert thread.is_alive(), "shipper must never crash on an oversized message"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant_id}'")


def test_shipper_resumes_from_persisted_offset_after_restart(tmp_path, kafka_bootstrap, kafka_topic, real_alert_lines):
    alerts_path = tmp_path / "alerts.json"
    offset_file = tmp_path / "offsets.json"
    alerts_path.write_text(real_alert_lines[0] + "\n")

    stop_flag, thread, metrics = _run_shipper_once(tmp_path, kafka_bootstrap, kafka_topic, alerts_path, offset_file)
    _drain_topic(kafka_bootstrap, kafka_topic, 1)
    stop_flag.set()
    thread.join(timeout=5)
    assert json.loads(offset_file.read_text())["alerts.json"]["offset"] > 0

    with open(alerts_path, "a") as f:
        f.write(real_alert_lines[1] + "\n")

    stop_flag2, thread2, metrics2 = _run_shipper_once(tmp_path, kafka_bootstrap, kafka_topic, alerts_path, offset_file)
    messages = _drain_topic(kafka_bootstrap, kafka_topic, 2)
    stop_flag2.set()
    thread2.join(timeout=5)

    # Exactly 2 total across both runs - the restart did not re-send line 1.
    assert len(messages) == 2


def test_shipper_survives_log_rotation(tmp_path, kafka_bootstrap, kafka_topic, real_alert_lines):
    alerts_path = tmp_path / "alerts.json"
    offset_file = tmp_path / "offsets.json"
    alerts_path.write_text(real_alert_lines[0] + "\n")

    stop_flag, thread, metrics = _run_shipper_once(tmp_path, kafka_bootstrap, kafka_topic, alerts_path, offset_file)
    _drain_topic(kafka_bootstrap, kafka_topic, 1)

    # Simulate logrotate: rename the old file away, create a fresh one at
    # the same path (new inode).
    os.rename(alerts_path, tmp_path / "alerts.json.1")
    alerts_path.write_text(real_alert_lines[1] + "\n")

    messages = _drain_topic(kafka_bootstrap, kafka_topic, 2)
    stop_flag.set()
    thread.join(timeout=5)

    assert len(messages) == 2
