import threading
import time
import uuid

import pytest
from confluent_kafka import Producer

from conftest import TEST_CLICKHOUSE_DB, delete_topics_and_wait, insert_tenant
from shadowtracer_ingest import writer
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.metrics import Metrics
from shadowtracer_ingest.topics import tenant_from_alerts_topic


@pytest.fixture(autouse=True)
def _default_lab_tenant(pg_db):
    """Harmless leftover from before Phase 5.6 Item 1 - kafka_topic
    (conftest.py) now creates its own random tenant + real topic pair
    per test, which is what _produce's default tenant_id actually
    resolves to. Kept for any test that still references the literal
    "lab" tenant_key directly."""
    insert_tenant(pg_db, "lab")


def _produce(kafka_bootstrap, topic, lines, tenant_id=None):
    # Phase 5.6 Item 1: default is the topic's OWN tenant now (the
    # trusted identity writer.py actually checks against), not a fixed
    # "lab" - kafka_topic's real topic is never shadowtracer.t.lab.alerts,
    # so that default would otherwise trip the new tenant_topic_mismatch
    # check on nearly every test in this file. An explicit tenant_id is
    # still a literal override, for the handful of tests that deliberately
    # produce a header disagreeing with the topic.
    if tenant_id is None:
        tenant_id = tenant_from_alerts_topic(topic)
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    for line in lines:
        producer.produce(
            topic, value=line.encode(),
            headers=[("tenant_id", tenant_id.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
        )
    producer.flush(30)


def _start_writer(kafka_bootstrap, topic, ch_env, database_url):
    # Phase 5.6 Item 1: `topic` is accepted but unused now - writer.run()
    # pattern-subscribes to every tenant's topic, no specific one to pass
    # in any more. Kept as a parameter (not removed) so every existing
    # call site in this file (`_start_writer(kafka_bootstrap, kafka_topic, ...)`)
    # stays unchanged; the caller's kafka_topic fixture already created
    # the real topic before this runs, which is what actually matters.
    metrics = Metrics()
    stop_flag = threading.Event()
    started_flag = threading.Event()
    thread = threading.Thread(
        target=writer.run,
        kwargs=dict(
            bootstrap_servers=kafka_bootstrap,
            group_id=f"test-writer-{uuid.uuid4().hex[:8]}",
            clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
            clickhouse_user=ch_env["CLICKHOUSE_USER"],
            clickhouse_password=ch_env["CLICKHOUSE_PASSWORD"],
            clickhouse_database=TEST_CLICKHOUSE_DB,
            database_url=database_url,
            metrics=metrics,
            stop_flag=stop_flag,
            started_flag=started_flag,
            kafka_client_config=kafka_client_config_from_env(),
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
    kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines, database_url,
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

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        _produce(kafka_bootstrap, kafka_topic, lines)

        # Phase 5.6 Item 3: wait for BOTH signals in the same bounded loop,
        # not count-then-assert-metrics-immediately. Root cause of a real,
        # reproducible flake found by timestamping both sides directly: a
        # row committed via ch.insert() becomes visible to a DIFFERENT
        # connection's FINAL-deduplicated query before the ORIGINAL
        # inserting client's own HTTP call returns control to the writer
        # thread (measured ~380ms apart) - metrics.incr() only runs after
        # that return, so checking "count caught up" and then immediately
        # asserting on metrics with no grace period races a real, normal
        # ClickHouse response-latency window, not a bug in the writer.
        #
        # Phase 5.6 Item 1: 40s, not 20s - a brand-new consumer group's
        # pattern subscription (ALERTS_TOPIC_PATTERN) needs its own
        # group-join/assignment round trip before the first poll() can
        # return anything, on top of the ClickHouse-latency margin above;
        # measured ~11s in isolation, but a busy shared test Kafka
        # cluster (the full suite running many such groups back to back)
        # pushed that past 20s for real, confirmed by this exact test
        # passing reliably alone and failing only inside the full run.
        deadline = time.monotonic() + 40
        count = 0
        snap: dict = {}
        while time.monotonic() < deadline:
            count = _count_alert_ids(ch_client, alert_ids)
            snap = metrics.snapshot()
            if count == len(lines) and snap.get("messages_inserted", 0) >= len(lines) and snap.get("batches_committed", 0) >= 1:
                break
            time.sleep(0.5)

        assert count == len(lines), f"expected {len(lines)} rows drained into ClickHouse, got {count}"
        assert snap.get("messages_inserted", 0) >= len(lines), f"metrics never caught up: {snap}"
        assert snap.get("batches_committed", 0) >= 1, f"metrics never caught up: {snap}"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id IN ({','.join(repr(a) for a in alert_ids)})")


def test_writer_restart_mid_ingest_no_loss_no_duplicates(
    kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines, database_url,
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
                bootstrap_servers=kafka_bootstrap, group_id=gid,
                clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
                clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
                clickhouse_database=TEST_CLICKHOUSE_DB, database_url=database_url,
                metrics=metrics2, stop_flag=stop2, started_flag=started2,
                kafka_client_config=kafka_client_config_from_env(),
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
    # 40s, not 20s - see test_writer_is_actually_running_and_draining_
    # not_just_callable's own comment on this exact margin.
    deadline = time.monotonic() + 40
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


@pytest.mark.parametrize("first_pass", ["same_cut", "different_cut", "beyond_dedup_window"])
def test_replay_keeps_identity_counts_exact(first_pass, kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines, database_url):
    """docs/design/THROUGHPUT_FIXES.md 4a: the writer batches by size/time,
    so a replay may re-insert rows its first pass already wrote (different
    batch cut -> different insert_deduplication_token, or a token that fell
    out of replicated_deduplication_window). Counts must stay exact anyway:
    events is ReplacingMergeTree on the alert identity, the rollup counts
    uniqExact(cluster_node, alert_id), and raw rows converge to n on merge.

    same_cut:            produce everything, consume, replay everything.
    different_cut:       first pass trickles one message at a time (one
                         insert each), the replay drains them as one batch.
    beyond_dedup_window: replicated_deduplication_window=1, so the first
                         pass's token is forgotten before the replay."""
    import json
    import subprocess
    marker = uuid.uuid4().hex[:8]
    lines, alert_ids = [], []
    for i, line in enumerate(real_alert_lines):
        alert = json.loads(line)
        alert["id"] = f"{alert['id']}.{marker}.{i}"
        alert_ids.append(alert["id"])
        lines.append(json.dumps(alert))
    n = len(lines)
    group_id = f"test-replay-{marker}"
    ids = ",".join(f"'{a}'" for a in alert_ids)

    def run_once():
        stop_flag, started_flag = threading.Event(), threading.Event()
        thread = threading.Thread(
            target=writer.run,
            kwargs=dict(
                bootstrap_servers=kafka_bootstrap, group_id=group_id,
                clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
                clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
                clickhouse_database=TEST_CLICKHOUSE_DB, database_url=database_url,
                metrics=Metrics(), stop_flag=stop_flag, started_flag=started_flag,
                kafka_client_config=kafka_client_config_from_env(),
            ),
            daemon=True,
        )
        thread.start()
        started_flag.wait(timeout=10)
        return stop_flag, thread

    def q(sql):
        return ch_client.query(sql).result_rows[0][0]

    def identities():
        return q(f"SELECT uniqExact(cluster_node, alert_id) FROM events WHERE alert_id IN ({ids})")

    tenant = tenant_from_alerts_topic(kafka_topic)

    def rollup_total():
        return q(f"SELECT sum(c) FROM (SELECT uniqExactMerge(identity_state) AS c FROM events_hourly_rollup "
                 f"WHERE tenant_id = '{tenant}' GROUP BY tenant_id, hour, agent_id, rule_id, rule_level)") or 0

    def wait_for(pred, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not pred():
            time.sleep(0.5)

    if first_pass == "beyond_dedup_window":
        # Hashes are only pruned when the cleanup thread runs - make it run
        # every second on this test table so "beyond the window" is reached.
        ch_client.command("ALTER TABLE events MODIFY SETTING replicated_deduplication_window = 1, "
                          "cleanup_delay_period = 1, cleanup_delay_period_random_add = 0")
    try:
        rollup_before = rollup_total()

        stop1, t1 = run_once()
        if first_pass == "different_cut":
            for line in lines:  # each message alone -> idle-gap flush -> one insert per row
                _produce(kafka_bootstrap, kafka_topic, [line])
                time.sleep(1.5)
        else:
            _produce(kafka_bootstrap, kafka_topic, lines)
        wait_for(lambda: identities() == n)
        stop1.set()
        t1.join(timeout=5)
        assert identities() == n, "initial consume should land all n alerts"
        assert rollup_total() - rollup_before == n

        if first_pass == "beyond_dedup_window":
            # Push the first pass's block hash out of the 1-block window.
            ch_client.command("INSERT INTO events (tenant_id, time, cluster_node, alert_id) "
                              f"VALUES ('window-filler-{marker}', now64(3), 'filler', 'filler-{marker}')")
            zk = q(f"SELECT zookeeper_path FROM system.replicas WHERE database = '{TEST_CLICKHOUSE_DB}' AND table = 'events'")
            wait_for(lambda: q(f"SELECT count() FROM system.zookeeper WHERE path = '{zk}/blocks'") <= 1, 180)  # the new period applies after the thread's current sleep
            assert q(f"SELECT count() FROM system.zookeeper WHERE path = '{zk}/blocks'") <= 1, "first pass's block hash never left the window"

        subprocess.run(
            ["docker", "exec", "shadowtracer-lab-kafka-1", "/opt/kafka/bin/kafka-consumer-groups.sh",
             "--bootstrap-server", "localhost:9092", "--command-config", "/etc/kafka/certs/admin-client.properties",
             "--group", group_id, "--topic", kafka_topic, "--reset-offsets", "--to-earliest", "--execute"],
            check=True, capture_output=True,
        )
        raw_before_replay = q(f"SELECT count() FROM events WHERE alert_id IN ({ids})")
        stop2, t2 = run_once()
        if first_pass == "same_cut":
            time.sleep(8)  # nothing observable may change - give the replay time to (not) land
        else:
            wait_for(lambda: q(f"SELECT count() FROM events WHERE alert_id IN ({ids})") > raw_before_replay, 30)
        stop2.set()
        t2.join(timeout=5)

        raw_after_replay = q(f"SELECT count() FROM events WHERE alert_id IN ({ids})")
        if first_pass != "same_cut":
            assert raw_after_replay == 2 * n, f"precondition: this replay must really re-insert (raw {raw_after_replay}, n {n})"
        assert identities() == n, "uniqExact over the alert identity must stay n"
        assert q(f"SELECT count() FROM events FINAL WHERE alert_id IN ({ids})") == n, "FINAL must show n"
        assert rollup_total() - rollup_before == n, "rollup (uniqExact) must still grow by exactly n"
        ch_client.command("OPTIMIZE TABLE events FINAL")
        assert q(f"SELECT count() FROM events WHERE alert_id IN ({ids})") == n, "raw rows must converge to n after merge"
    finally:
        if first_pass == "beyond_dedup_window":
            ch_client.command("ALTER TABLE events RESET SETTING replicated_deduplication_window, "
                              "cleanup_delay_period, cleanup_delay_period_random_add")
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id IN ({ids}) OR tenant_id = 'window-filler-{marker}'")


def test_writer_dead_letters_bad_data_keeps_good_ones(kafka_bootstrap, kafka_topic, kafka_tenant_key, ch_client, lab_env, real_alert_lines, pg_db, database_url):
    """No single event may stop the pipeline: a batch mixing a permanently
    malformed event (one that fails normalize_alert, here via an invalid
    timestamp) with a good one must land the good one in ClickHouse,
    dead-letter the bad one (never retried - bad data, not a transient
    failure), and keep the writer running and committing offsets."""
    import json
    marker = uuid.uuid4().hex[:8]
    tenant_id = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one

    good = json.loads(real_alert_lines[0])
    good["id"] = f"{good['id']}.{marker}.good"
    bad = json.loads(real_alert_lines[1])
    bad["id"] = f"{bad['id']}.{marker}.bad"
    bad["timestamp"] = "2026-10-04T05:00:118.000+0000"  # seconds=118: not valid ISO8601

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        _produce(kafka_bootstrap, kafka_topic, [json.dumps(good), json.dumps(bad)], tenant_id=tenant_id)

        deadline = time.monotonic() + 40  # Phase 5.6 Item 1: see test_writer_is_actually_running_and_draining_not_just_callable's own comment on this margin
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


def test_writer_stays_up_when_dead_letter_clickhouse_insert_fails(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, ch_client, lab_env, real_alert_lines, pg_db, database_url,
):
    """Dead-letter-ClickHouse incident (2026-10-08) hardening, at the real
    writer.run() level: the dead_letter_events table itself is unreachable
    (a real, atomic RENAME TABLE - never the Keeper surgery that caused
    the real incident - restored in `finally`), while the events table
    the writer ALSO writes to stays healthy. A permanently malformed
    event must still not crash the writer, must still land on the Kafka
    dead-letter topic (published before the ClickHouse attempt - see
    dead_letter.py), must count dead_letter_ch_failures, and the good
    event right behind it must still land in ClickHouse."""
    import json
    marker = uuid.uuid4().hex[:8]
    # Phase 5.6 Item 1: kafka_topic's own tenant now - this test's topic
    # (from kafka_topic) belongs to kafka_tenant_key, so producing under
    # a DIFFERENT tenant_id here would trip tenant_topic_mismatch instead
    # of exercising what this test is actually about (a ClickHouse-side
    # dead-letter failure).
    tenant_id = kafka_tenant_key
    good = json.loads(real_alert_lines[0])
    good["id"] = f"{good['id']}.{marker}.good"
    bad = json.loads(real_alert_lines[1])
    bad["id"] = f"{bad['id']}.{marker}.bad"
    bad["timestamp"] = "2026-10-04T05:00:118.000+0000"  # not valid ISO8601

    tmp_name = f"dead_letter_events_tmp_{marker}"
    ch_client.command(
        f"RENAME TABLE {TEST_CLICKHOUSE_DB}.dead_letter_events TO {TEST_CLICKHOUSE_DB}.{tmp_name} ON CLUSTER lab_cluster"
    )
    try:
        stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
        try:
            _produce(kafka_bootstrap, kafka_topic, [json.dumps(bad), json.dumps(good)], tenant_id=tenant_id)

            deadline = time.monotonic() + 40  # Phase 5.6 Item 1: see test_writer_is_actually_running_and_draining_not_just_callable's own comment on this margin
            good_count = 0
            while time.monotonic() < deadline:
                good_count = _count_alert_ids(ch_client, [good["id"]])
                if good_count == 1 and metrics.snapshot().get("dead_letter_ch_failures", 0) >= 1:
                    break
                time.sleep(0.5)

            assert good_count == 1, "the good event right behind the dead-lettered one must still land in ClickHouse"
            assert thread.is_alive(), "writer must never crash when the dead-letter ClickHouse insert fails"
            assert metrics.snapshot().get("dead_letter_ch_failures", 0) >= 1

            from confluent_kafka import Consumer
            from shadowtracer_ingest.topics import dead_letter_topic_for_tenant
            drain = Consumer({
                "bootstrap.servers": kafka_bootstrap,
                "group.id": f"test-dlt-drain-{marker}",
                "auto.offset.reset": "earliest",
                **kafka_client_config_from_env(),
            })
            drain.subscribe([dead_letter_topic_for_tenant(tenant_id)])
            found = None
            drain_deadline = time.monotonic() + 30  # Phase 5.6 Item 1: same margin as the deadline= polls above
            while time.monotonic() < drain_deadline:
                msg = drain.poll(1.0)
                if msg is not None and msg.error() is None and bad["id"] in msg.value().decode():
                    found = msg.value().decode()
                    break
            drain.close()
            assert found is not None, "the Kafka dead-letter topic copy must still land even when ClickHouse fails"
        finally:
            stop_flag.set()
            thread.join(timeout=5)
            ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id = '{good['id']}'")
    finally:
        ch_client.command(
            f"RENAME TABLE {TEST_CLICKHOUSE_DB}.{tmp_name} TO {TEST_CLICKHOUSE_DB}.dead_letter_events ON CLUSTER lab_cluster"
        )


def test_dead_letter_kafka_failure_is_never_swallowed_offset_would_not_advance():
    """Unit-level proof of the EXACT composition writer.py's (and
    consumer.py's) dead-letter call site uses:
    retry_with_backoff(lambda: send_to_dead_letter(...), max_attempts=None,
    stop_flag=stop_flag). When the Kafka dead-letter publish itself fails
    (a real unreachable broker - send_to_dead_letter raises, never
    swallows it - see test_dead_letter.py), this composition must keep
    retrying rather than return normally, so the caller never reaches the
    commit that would advance past this message with no durable record
    anywhere. Proven by firing stop_flag mid-retry (a graceful shutdown)
    and confirming retry_with_backoff still raises rather than returning -
    the one case its own docstring says it should (see test_retry.py for
    that contract in isolation)."""
    import threading

    from confluent_kafka import Producer

    from shadowtracer_ingest.dead_letter import send_to_dead_letter
    from shadowtracer_ingest.retry import retry_with_backoff

    unreachable_producer = Producer({"bootstrap.servers": "127.0.0.1:1", "message.timeout.ms": 2000})
    stop_flag = threading.Event()
    threading.Timer(1.0, stop_flag.set).start()

    try:
        retry_with_backoff(
            lambda: send_to_dead_letter(
                kafka_producer=unreachable_producer, ch_client=None, tenant_key="test",
                component="writer", source_location="x", error="x", raw_event="{}",
            ),
            max_attempts=None, base_delay=0.5, max_delay=1.0, stop_flag=stop_flag,
        )
        assert False, "must raise, never return normally, when the Kafka dead-letter publish never succeeds"
    except RuntimeError as exc:
        assert "did not durably succeed" in str(exc)


def test_writer_dead_letters_unknown_tenant_known_tenant_still_processes(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, ch_client, lab_env, real_alert_lines, pg_db, database_url,
):
    """Phase 5C Step 0: a tenant_key with no backing tenants row must be
    dead-lettered (error="unknown_tenant"), never stored - proven
    alongside a real, flagged-as-test tenant (kafka_topic's own, already
    with a real tenants row) whose otherwise-identical event still lands
    normally, so this isn't just "the writer dead-letters everything
    right now".

    Phase 5.6 Item 1: "unknown tenant" now means a topic exists (a real
    producer ACL was granted for it) but its Postgres row doesn't - the
    tenant_cache staleness race this item was originally written for,
    not "no topic at all" (which isn't reachable: a message can't exist
    without a provisioned topic to carry it). Needs its own topic,
    created here with no matching tenants row, since kafka_topic's own
    topic always has one by construction."""
    import json
    from confluent_kafka.admin import AdminClient, NewTopic
    from shadowtracer_ingest.topics import alerts_topic_for_tenant, dead_letter_topic_for_tenant
    marker = uuid.uuid4().hex[:8]
    known_tenant = kafka_tenant_key
    unknown_tenant = f"test-unknown-{marker}"  # topic provisioned below, deliberately never inserted into tenants
    unknown_topic = alerts_topic_for_tenant(unknown_tenant)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    # Both topics, as create-kafka-topics.sh provisions them: the tenant row is
    # what's missing here, not its topics (an offboarded tenant whose topics
    # are gone too is test_offboarded_tenant_message_does_not_stall_other_tenants).
    admin.create_topics([NewTopic(unknown_topic, num_partitions=1, replication_factor=1),
                         NewTopic(dead_letter_topic_for_tenant(unknown_tenant), num_partitions=1, replication_factor=1)])
    time.sleep(1)

    known_event = json.loads(real_alert_lines[0])
    known_event["id"] = f"{known_event['id']}.{marker}.known"
    unknown_event = json.loads(real_alert_lines[1])
    unknown_event["id"] = f"{unknown_event['id']}.{marker}.unknown"

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
        producer.produce(
            kafka_topic, value=json.dumps(known_event).encode(),
            headers=[("tenant_id", known_tenant.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
        )
        producer.produce(
            unknown_topic, value=json.dumps(unknown_event).encode(),
            headers=[("tenant_id", unknown_tenant.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
        )
        producer.flush(30)

        # 40s, not 20s - see test_writer_is_actually_running_and_draining_
        # not_just_callable's own comment on this exact margin.
        deadline = time.monotonic() + 40
        known_count = dl_count = 0
        while time.monotonic() < deadline:
            known_count = _count_alert_ids(ch_client, [known_event["id"]])
            dl_count = ch_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{unknown_tenant}' AND error = 'unknown_tenant'"
            ).result_rows[0][0]
            if known_count == 1 and dl_count == 1:
                break
            time.sleep(0.5)

        assert known_count == 1, "the known (flagged-test) tenant's event must still land in ClickHouse"
        assert dl_count == 1, "the unknown tenant's event must be dead-lettered with error=unknown_tenant"
        assert _count_alert_ids(ch_client, [unknown_event["id"]]) == 0, "the unknown tenant's event must never be stored"
        assert thread.is_alive(), "writer must never crash on an unknown tenant"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id = '{known_event['id']}'")
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{unknown_tenant}'")
        # The dead-letter topic was never explicitly created above (see
        # this test's own docstring), but the writer's own dead-letter
        # produce for the unknown-tenant event brings it into existence
        # anyway - confirmed left behind every run until this was added.
        from shadowtracer_ingest.topics import dead_letter_topic_for_tenant
        delete_topics_and_wait(admin, [unknown_topic, dead_letter_topic_for_tenant(unknown_tenant)])


def test_writer_dead_letters_unsupported_envelope_version_known_version_still_processes(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, ch_client, lab_env, real_alert_lines, pg_db, database_url,
):
    """Phase 5.6 Item 4: an envelope_version header this writer doesn't
    recognize must be dead-lettered (error starts "unsupported_envelope_
    version"), never stored - proven alongside an otherwise-identical
    event at the real, current ENVELOPE_VERSION that still lands
    normally, same shape as the unknown_tenant test above."""
    import json
    from shadowtracer_ingest.writer import ENVELOPE_VERSION
    marker = uuid.uuid4().hex[:8]
    tenant_key = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one

    known_event = json.loads(real_alert_lines[0])
    known_event["id"] = f"{known_event['id']}.{marker}.known"
    future_event = json.loads(real_alert_lines[1])
    future_event["id"] = f"{future_event['id']}.{marker}.future"

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
        producer.produce(
            kafka_topic, value=json.dumps(known_event).encode(),
            headers=[
                ("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json"),
                ("envelope_version", str(ENVELOPE_VERSION).encode()),
            ],
        )
        producer.produce(
            kafka_topic, value=json.dumps(future_event).encode(),
            headers=[
                ("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json"),
                ("envelope_version", b"99"),
            ],
        )
        producer.flush(30)

        deadline = time.monotonic() + 40  # Phase 5.6 Item 1: see test_writer_is_actually_running_and_draining_not_just_callable's own comment on this margin
        known_count = dl_count = 0
        while time.monotonic() < deadline:
            known_count = _count_alert_ids(ch_client, [known_event["id"]])
            dl_count = ch_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant_key}' "
                f"AND error LIKE 'unsupported_envelope_version%'"
            ).result_rows[0][0]
            if known_count == 1 and dl_count == 1:
                break
            time.sleep(0.5)

        assert known_count == 1, "the event at the real ENVELOPE_VERSION must still land in ClickHouse"
        assert dl_count == 1, "the unsupported-version event must be dead-lettered with error=unsupported_envelope_version..."
        assert _count_alert_ids(ch_client, [future_event["id"]]) == 0, "the unsupported-version event must never be stored"
        assert thread.is_alive(), "writer must never crash on an unsupported envelope version"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id = '{known_event['id']}'")
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant_key}'")


def test_writer_replay_of_pre_envelope_version_messages_is_processed_not_dead_lettered(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, ch_client, lab_env, real_alert_lines, pg_db, database_url,
):
    """Phase 5.6 Item 4, follow-up request: a message with NO
    envelope_version header at all - the real shape of every message
    this project ever produced before Item 4 existed, which could still
    be sitting in Kafka's 7-day retention window or get replayed from a
    dead-letter backup after this writer is upgraded (the exact kind of
    gap that caused the 46 unrecoverable dead letters VERSIONING.md Sec
    0 describes) - must be treated as version 1 and processed normally,
    never dead-lettered just for lacking the header. Produced directly
    via raw Producer.produce(), deliberately NOT through shipper.py (which
    always sets the header now), to reproduce the real pre-change wire
    shape exactly, not an approximation of it."""
    import json
    marker = uuid.uuid4().hex[:8]
    tenant_key = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one

    events = []
    for i in range(3):
        event = json.loads(real_alert_lines[i])
        event["id"] = f"{event['id']}.{marker}.{i}"
        events.append(event)

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
        for event in events:
            producer.produce(
                kafka_topic, value=json.dumps(event).encode(),
                # Deliberately no envelope_version header - the real,
                # exact shape shipper.py produced before Item 4.
                headers=[("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
            )
        producer.flush(30)

        alert_ids = [e["id"] for e in events]
        deadline = time.monotonic() + 40  # Phase 5.6 Item 1: see test_writer_is_actually_running_and_draining_not_just_callable's own comment on this margin
        count = dl_count = 0
        while time.monotonic() < deadline:
            count = _count_alert_ids(ch_client, alert_ids)
            dl_count = ch_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant_key}'"
            ).result_rows[0][0]
            if count == len(events):
                break
            time.sleep(0.5)

        assert count == len(events), f"pre-change (no header) messages must still land in ClickHouse, got {count}/{len(events)}"
        assert dl_count == 0, "a missing envelope_version header must never be treated as unsupported/dead-lettered"
        assert thread.is_alive(), "writer must never crash on a message with no envelope_version header"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        ch_client.command(f"ALTER TABLE events DELETE WHERE tenant_id = '{tenant_key}'")


def test_a_brand_new_tenants_first_event_sent_right_away_is_stored_not_dead_lettered(
    kafka_bootstrap, kafka_topic, ch_client, lab_env, pg_db, database_url, real_alert_lines,
):
    """Phase 5C Step 0 follow-up: TenantCache refreshes immediately on a
    miss (rate-limited to at most once per second, not the old 15s
    window) - a tenant created THEN its first event produced with no
    delay at all must still land normally, not get dead-lettered as
    unknown_tenant just because the cache hadn't seen it yet.

    Phase 5.6 Item 1: needs its OWN topic, created WITHOUT a tenants row
    yet - kafka_topic's own tenant is never "brand new" by the time a
    test body runs (its tenants row is inserted at fixture setup, before
    this test even starts), which would defeat the exact race this test
    exists to exercise."""
    import json
    from confluent_kafka.admin import AdminClient, NewTopic
    from shadowtracer_ingest.topics import alerts_topic_for_tenant
    marker = uuid.uuid4().hex[:8]
    tenant_key = f"test-brand-new-{marker}"
    brand_new_topic = alerts_topic_for_tenant(tenant_key)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    admin.create_topics([NewTopic(brand_new_topic, num_partitions=1, replication_factor=1)])
    time.sleep(1)

    event = json.loads(real_alert_lines[0])
    event["id"] = f"{event['id']}.{marker}"

    stop_flag, thread, metrics = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        insert_tenant(pg_db, tenant_key)
        _produce(kafka_bootstrap, brand_new_topic, [json.dumps(event)])  # no delay

        deadline = time.monotonic() + 40  # Phase 5.6 Item 1: see test_writer_is_actually_running_and_draining_not_just_callable's own comment on this margin
        count = 0
        while time.monotonic() < deadline:
            count = _count_alert_ids(ch_client, [event["id"]])
            if count == 1:
                break
            time.sleep(0.5)
        assert count == 1, "a brand-new tenant's first event, sent right away, must still be stored"

        dl_count = ch_client.query(
            f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant_key}' AND error = 'unknown_tenant'"
        ).result_rows[0][0]
        assert dl_count == 0, "must not have been dead-lettered as unknown_tenant on the way there"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        delete_topics_and_wait(admin, [brand_new_topic])
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id = '{event['id']}'")


def test_offboarded_tenant_message_does_not_stall_other_tenants(kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines, database_url):
    """Tenant offboarding (docs/design/TENANCY.md §6): a message still in an
    offboarded tenant's alerts topic - tenants row gone, dead-letter topic
    deleted - must be recorded and skipped, while another tenant's alerts
    keep landing. Before the fix the writer retried the dead-letter publish
    forever and every partition it owned stopped."""
    import json
    from confluent_kafka.admin import AdminClient, NewTopic
    from shadowtracer_ingest.topics import alerts_topic_for_tenant

    marker = uuid.uuid4().hex[:8]
    offboarded = f"test-off-{marker}"  # no tenants row, no dead-letter topic
    off_topic = alerts_topic_for_tenant(offboarded)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    admin.create_topics([NewTopic(off_topic, num_partitions=1, replication_factor=1)])[off_topic].result(30)

    good_ids, good_lines = [], []
    for i, line in enumerate(real_alert_lines):
        alert = json.loads(line)
        alert["id"] = f"{alert['id']}.{marker}.{i}"
        good_ids.append(alert["id"])
        good_lines.append(json.dumps(alert))
    try:
        _produce(kafka_bootstrap, off_topic, [real_alert_lines[0]])
        stop_flag, started_flag, metrics = threading.Event(), threading.Event(), Metrics()
        thread = threading.Thread(target=writer.run, daemon=True, kwargs=dict(
            bootstrap_servers=kafka_bootstrap, group_id=f"test-writer-off-{marker}",
            clickhouse_hosts=[("127.0.0.1", 8123), ("127.0.0.1", 8124)],
            clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
            clickhouse_database=TEST_CLICKHOUSE_DB, database_url=database_url, metrics=metrics,
            stop_flag=stop_flag, started_flag=started_flag,
            # As the lab's writer principal: no topic creation.
            kafka_client_config={**kafka_client_config_from_env(), "allow.auto.create.topics": False},
        ))
        thread.start()
        assert started_flag.wait(10)
        time.sleep(3)  # let it reach the offboarded message first
        _produce(kafka_bootstrap, kafka_topic, good_lines)

        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and _count_alert_ids(ch_client, good_ids) < len(good_ids):
            time.sleep(0.5)
        stop_flag.set()
        thread.join(timeout=10)

        assert _count_alert_ids(ch_client, good_ids) == len(good_ids), "the other tenant's alerts must keep landing"
        rows = ch_client.query("SELECT error FROM dead_letter_events WHERE tenant_id = {t:String}",
                               parameters={"t": offboarded}).result_rows
        assert rows and "unknown_tenant" in rows[0][0] and "tenant offboarded" in rows[0][0], rows
        assert metrics.snapshot().get("dead_letter_topic_missing", 0) >= 1
    finally:
        delete_topics_and_wait(admin, [off_topic])
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{offboarded}'")


def test_writer_survives_a_topic_deleted_while_it_runs(kafka_bootstrap, kafka_topic, ch_client, lab_env, real_alert_lines, pg_db, database_url):
    """A topic deleted after the writer consumed from it (tenant offboarding,
    or a suite tearing down its topics) used to crash the writer at its next
    commit: KafkaException UNKNOWN_TOPIC_OR_PART (seen as 9 and 6 lab writer
    restarts). It must keep running and keep landing other tenants' rows."""
    import json
    from confluent_kafka.admin import AdminClient, NewTopic
    from shadowtracer_ingest.topics import alerts_topic_for_tenant, dead_letter_topic_for_tenant

    marker = uuid.uuid4().hex[:8]
    gone = f"test-gone-{marker}"
    insert_tenant(pg_db, gone)
    gone_topics = [alerts_topic_for_tenant(gone), dead_letter_topic_for_tenant(gone)]
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    for f in admin.create_topics([NewTopic(t, num_partitions=1, replication_factor=1) for t in gone_topics]).values():
        f.result(30)

    def lines(tag):
        out = []
        for i, line in enumerate(real_alert_lines):
            alert = json.loads(line)
            alert["id"] = f"{alert['id']}.{marker}.{tag}{i}"
            out.append(json.dumps(alert))
        return out, [json.loads(x)["id"] for x in out]

    gone_lines, gone_ids = lines("g")
    later_lines, later_ids = lines("k")
    stop_flag, thread, _ = _start_writer(kafka_bootstrap, kafka_topic, lab_env, database_url)
    try:
        _produce(kafka_bootstrap, gone_topics[0], gone_lines)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and _count_alert_ids(ch_client, gone_ids) < len(gone_ids):
            time.sleep(0.5)
        assert _count_alert_ids(ch_client, gone_ids) == len(gone_ids)

        delete_topics_and_wait(admin, gone_topics)
        _produce(kafka_bootstrap, kafka_topic, later_lines)  # the next commit still covers the deleted partition
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and _count_alert_ids(ch_client, later_ids) < len(later_ids):
            time.sleep(0.5)
        assert thread.is_alive(), "the writer must not crash when a consumed topic is deleted"
        assert _count_alert_ids(ch_client, later_ids) == len(later_ids), "other tenants' rows must keep landing"
    finally:
        stop_flag.set()
        thread.join(timeout=10)
        ch_client.command(f"ALTER TABLE events DELETE WHERE alert_id IN ({','.join(repr(a) for a in gone_ids + later_ids)})")
