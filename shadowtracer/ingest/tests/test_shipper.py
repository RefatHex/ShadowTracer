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
