import threading
import time
import uuid

from confluent_kafka import Producer

from conftest import TEST_CLICKHOUSE_DB
from shadowtracer_ingest import writer
from shadowtracer_ingest.metrics import Metrics


def _produce(kafka_bootstrap, topic, lines, tenant_id="lab"):
    producer = Producer({"bootstrap.servers": kafka_bootstrap})
    for line in lines:
        producer.produce(
            topic, value=line.encode(),
            headers=[("tenant_id", tenant_id.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
        )
    producer.flush(30)


def _start_writer(kafka_bootstrap, topic, ch_env):
    metrics = Metrics()
    stop_flag = threading.Event()
    started_flag = threading.Event()
    thread = threading.Thread(
        target=writer.run,
        kwargs=dict(
            bootstrap_servers=kafka_bootstrap,
            topic=topic,
            group_id=f"test-writer-{uuid.uuid4().hex[:8]}",
            clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
            clickhouse_user=ch_env["CLICKHOUSE_USER"],
            clickhouse_password=ch_env["CLICKHOUSE_PASSWORD"],
            clickhouse_database=TEST_CLICKHOUSE_DB,
            metrics=metrics,
            stop_flag=stop_flag,
            started_flag=started_flag,
        ),
        daemon=True,
    )
    thread.start()
    assert started_flag.wait(timeout=10), "writer never signalled started"
    return stop_flag, thread, metrics


def _count_alert_ids(ch_client, alert_ids):
    placeholders = ",".join(f"'{a}'" for a in alert_ids)
    return ch_client.query(f"SELECT count() FROM events FINAL WHERE alert_id IN ({placeholders})").result_rows[0][0]


def test_writer_is_actually_running_and_draining_not_just_callable(
    kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines,
):
    """Proves the writer's main loop is live: we never call normalize_alert
    or insert_batch directly here - we only start writer.run() in a thread
    and produce to Kafka, exactly like a real deployment would."""
    marker = uuid.uuid4().hex[:8]
    lines = []
    alert_ids = []
    for i, line in enumerate(real_alert_lines[:3]):
        import json
        alert = json.loads(line)
        alert["id"] = f"{alert['id']}.{marker}.{i}"
        alert_ids.append(alert["id"])
        lines.append(json.dumps(alert))

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env)
    try:
        _produce(kafka_bootstrap, kafka_topic, lines)

        deadline = time.monotonic() + 20
        count = 0
        while time.monotonic() < deadline:
            count = _count_alert_ids(ch_client, alert_ids)
            if count == len(lines):
                break
            time.sleep(0.5)

        assert count == len(lines), f"expected {len(lines)} rows drained into ClickHouse, got {count}"
        assert metrics.snapshot()["messages_inserted"] >= len(lines)
        assert metrics.snapshot()["batches_committed"] >= 1
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id IN ({','.join(repr(a) for a in alert_ids)})")


def test_writer_restart_mid_ingest_no_loss_no_duplicates(
    kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines,
):
    import json
    marker = uuid.uuid4().hex[:8]
    lines = []
    alert_ids = []
    for i, line in enumerate(real_alert_lines):
        alert = json.loads(line)
        alert["id"] = f"{alert['id']}.{marker}.{i}"
        alert_ids.append(alert["id"])
        lines.append(json.dumps(alert))

    _produce(kafka_bootstrap, kafka_topic, lines)

    # Same consumer group id across both starts - that's what makes this a
    # real restart (resuming from last committed offset) rather than two
    # independent readers.
    group_id = f"test-writer-restart-{marker}"

    def start_with_group(gid):
        metrics2 = Metrics()
        stop2 = threading.Event()
        started2 = threading.Event()
        t = threading.Thread(
            target=writer.run,
            kwargs=dict(
                bootstrap_servers=kafka_bootstrap, topic=kafka_topic, group_id=gid,
                clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
                clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
                clickhouse_database=TEST_CLICKHOUSE_DB, metrics=metrics2, stop_flag=stop2, started_flag=started2,
            ),
            daemon=True,
        )
        t.start()
        started2.wait(timeout=10)
        return stop2, t, metrics2

    stop1, t1, m1 = start_with_group(group_id)
    time.sleep(2)
    stop1.set()
    t1.join(timeout=5)

    stop2, t2, m2 = start_with_group(group_id)
    deadline = time.monotonic() + 20
    count = 0
    while time.monotonic() < deadline:
        count = _count_alert_ids(ch_client, alert_ids)
        if count == len(lines):
            break
        time.sleep(0.5)
    stop2.set()
    t2.join(timeout=5)

    assert count == len(lines), f"expected {len(lines)} deduped rows after restart, got {count}"
    ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id IN ({','.join(repr(a) for a in alert_ids)})")


def test_replay_does_not_inflate_base_table_or_rollup(kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines):
    """Phase 3 follow-up 1: reproduces the exact bug (replay inflating the
    hourly rollup even though the base table's FINAL was already correct)
    and proves both fixes - the per-partition insert_deduplication_token
    (base table correct even WITHOUT FINAL) and the rollup's uniqExact
    identity count (correct regardless of the token fix) - through the
    real writer.run(), not manual SQL."""
    import json
    marker = uuid.uuid4().hex[:8]
    lines = []
    alert_ids = []
    for i, line in enumerate(real_alert_lines):
        alert = json.loads(line)
        alert["id"] = f"{alert['id']}.{marker}.{i}"
        alert_ids.append(alert["id"])
        lines.append(json.dumps(alert))
    n = len(lines)

    group_id = f"test-replay-{marker}"

    def run_once():
        metrics = Metrics()
        stop_flag = threading.Event()
        started_flag = threading.Event()
        thread = threading.Thread(
            target=writer.run,
            kwargs=dict(
                bootstrap_servers=kafka_bootstrap, topic=kafka_topic, group_id=group_id,
                clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
                clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
                clickhouse_database=TEST_CLICKHOUSE_DB, metrics=metrics, stop_flag=stop_flag, started_flag=started_flag,
            ),
            daemon=True,
        )
        thread.start()
        started_flag.wait(timeout=10)
        return stop_flag, thread

    def raw_count():
        placeholders = ",".join(f"'{a}'" for a in alert_ids)
        return ch_client.query(f"SELECT count() FROM events WHERE alert_id IN ({placeholders})").result_rows[0][0]

    def rollup_total():
        # events_hourly_rollup groups by (tenant_id, hour, agent_id, rule_id,
        # rule_level), not alert_id, so other tests sharing the fixture's
        # agent/rule ids contribute to the same buckets - measure the DELTA
        # this test causes, not an absolute value.
        return ch_client.query("SELECT sum(c) FROM (SELECT uniqExactMerge(identity_state) AS c FROM events_hourly_rollup GROUP BY tenant_id, hour, agent_id, rule_id, rule_level)").result_rows[0][0] or 0

    rollup_before = rollup_total()

    _produce(kafka_bootstrap, kafka_topic, lines)
    stop1, t1 = run_once()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and raw_count() < n:
        time.sleep(0.5)
    stop1.set()
    t1.join(timeout=5)
    assert raw_count() == n, "initial consume should land exactly n rows"
    rollup_after_first = rollup_total()
    assert rollup_after_first - rollup_before == n, (
        f"rollup should grow by exactly {n} after the initial consume, "
        f"grew by {rollup_after_first - rollup_before}"
    )

    # Replay: same consumer group, reset to earliest.
    import subprocess
    subprocess.run(
        ["docker", "exec", "shadowtracer-lab-kafka-1", "/opt/kafka/bin/kafka-consumer-groups.sh",
         "--bootstrap-server", "localhost:9092", "--group", group_id, "--topic", kafka_topic,
         "--reset-offsets", "--to-earliest", "--execute"],
        check=True, capture_output=True,
    )

    stop2, t2 = run_once()
    time.sleep(8)  # let the full replay drain
    stop2.set()
    t2.join(timeout=5)

    assert raw_count() == n, f"base table WITHOUT FINAL must show exactly {n} after replay, not {n*2} (insert_deduplication_token)"
    rollup_after_replay = rollup_total()
    assert rollup_after_replay - rollup_before == n, (
        f"rollup must still show exactly {n} after replay (uniqExact), "
        f"grew by {rollup_after_replay - rollup_before} total"
    )

    ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id IN ({','.join(repr(a) for a in alert_ids)})")


def test_writer_dead_letters_bad_data_keeps_good_ones(kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines):
    """No single event may stop the pipeline: a batch mixing a permanently
    malformed event (one that fails normalize_alert, here via an invalid
    timestamp) with a good one must land the good one in ClickHouse,
    dead-letter the bad one (never retried - bad data, not a transient
    failure), and keep the writer running and committing offsets."""
    import json
    marker = uuid.uuid4().hex[:8]
    tenant_id = f"test-{marker}"

    good = json.loads(real_alert_lines[0])
    good["id"] = f"{good['id']}.{marker}.good"
    bad = json.loads(real_alert_lines[1])
    bad["id"] = f"{bad['id']}.{marker}.bad"
    bad["timestamp"] = "2026-10-04T05:00:118.000+0000"  # seconds=118: not valid ISO8601

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env)
    try:
        _produce(kafka_bootstrap, kafka_topic, [json.dumps(good), json.dumps(bad)], tenant_id=tenant_id)

        deadline = time.monotonic() + 20
        good_count = dl_count = 0
        while time.monotonic() < deadline:
            good_count = _count_alert_ids(ch_client, [good["id"]])
            dl_count = ch_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant_id}' AND component = 'writer'"
            ).result_rows[0][0]
            if good_count == 1 and dl_count == 1:
                break
            time.sleep(0.5)

        assert good_count == 1, "the good event must still land in ClickHouse"
        assert dl_count == 1, "the bad event must be dead-lettered, not silently dropped or crash the writer"
        assert thread.is_alive(), "writer must never crash on bad data"
        assert metrics.snapshot()["messages_failed"] >= 1
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id = '{good['id']}'")
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant_id}'")


def test_failover_clickhouse_skips_a_dead_host():
    """Unit-level proof of _FailoverClickHouse's own logic: a bogus first
    host must not stop the insert from landing on the second, real one."""
    from shadowtracer_ingest.writer import _FailoverClickHouse
    import os

    env = {}
    with open(os.path.join(os.path.dirname(__file__), "..", "..", "..", "deploy", "lab", ".env")) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v

    ch = _FailoverClickHouse(
        hosts=[("127.0.0.1", 1), ("127.0.0.1", 8123)],  # port 1: nothing listens there
        user=env["CLICKHOUSE_USER"], password=env["CLICKHOUSE_PASSWORD"], database=TEST_CLICKHOUSE_DB,
    )
    used = ch.insert("events", [], column_names=["tenant_id"])
    assert used == 1  # fell through to the second (working) host
