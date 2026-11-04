import json
import re
import subprocess
import threading
import time
import uuid

from confluent_kafka import Consumer, Producer
from sqlalchemy import select

from conftest import TEST_CLICKHOUSE_DB, TEST_TOPIC_PATTERN, delete_topics_and_wait, insert_tenant
from shadowtracer_correlate.consumer import run
from shadowtracer_correlate.metrics import Metrics
from shadowtracer_correlate.models import incident_alerts, incidents
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
from shadowtracer_ingest.topics import alerts_topic_for_tenant, dead_letter_topic_for_tenant, tenant_from_alerts_topic


def _alert(agent_id: str, src_ip: str, alert_id: str, timestamp: str = "2026-01-01T12:00:00.000+0000") -> str:
    return json.dumps({
        "timestamp": timestamp,
        "id": alert_id,
        "rule": {"id": "5710", "level": 5, "description": "sshd failure", "groups": ["sshd"]},
        "agent": {"id": agent_id, "name": agent_id, "ip": "10.0.0.1"},
        "manager": {"name": "wazuh-worker1"},
        "cluster": {"node": "worker1"},
        "data": {"srcip": src_ip},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"Invalid user test from {src_ip}",
    })


def _produce(kafka_bootstrap, topic, lines, tenant_key=None):
    """Phase 5.6 Item 1: default tenant_key is the topic's OWN tenant now
    (the trusted identity consumer.py actually checks against), not a
    fixed "lab" - see shadowtracer_ingest/tests/test_writer.py's
    identical _produce fix for why. Keys each message by agent_id alone
    now - tenant is the topic itself, not part of the key - which is
    what actually guarantees one agent's events all land on the same
    partition, owned by exactly one worker. A test that produced without
    this key would let two different workers legitimately race on the
    same agent, which can't happen for real."""
    if tenant_key is None:
        tenant_key = tenant_from_alerts_topic(topic)
    producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    for line in lines:
        agent_id = json.loads(line)["agent"]["id"]
        producer.produce(
            topic, value=line.encode(), key=agent_id.encode(),
            headers=[("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
        )
    producer.flush(30)


def _start_consumer(kafka_bootstrap, topic, database_url, group_id=None, ch_client=None, kafka_config_extra=None,
                    topic_pattern=TEST_TOPIC_PATTERN):
    # Phase 5.6 Item 1: `topic` is accepted but unused now - consumer.run()
    # pattern-subscribes to every tenant's topic (same as writer.py);
    # kept as a parameter so every existing call site in this file stays
    # unchanged - the caller's kafka_topic fixture already created the
    # real topic before this runs, which is what actually matters.
    metrics = Metrics()
    stop_flag = threading.Event()
    started_flag = threading.Event()
    thread = threading.Thread(
        target=run,
        kwargs=dict(
            bootstrap_servers=kafka_bootstrap,
            group_id=group_id or f"test-correlate-{uuid.uuid4().hex[:8]}",
            database_url=database_url, metrics=metrics,
            stop_flag=stop_flag, started_flag=started_flag, ch_client=ch_client,
            kafka_client_config={**kafka_client_config_from_env(), **(kafka_config_extra or {})},
            topic_pattern=topic_pattern,
        ),
        daemon=True,
    )
    thread.start()
    assert started_flag.wait(timeout=10), "consumer never signalled started"
    return stop_flag, thread, metrics


def test_correlator_is_actually_running_and_draining_not_just_callable(kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db):
    """Proves the consumer's main loop is live: we never call process_event
    directly here - we only start consumer.run() in a thread and produce
    to Kafka, exactly like a real deployment would."""
    tenant = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    marker = uuid.uuid4().hex[:8]
    agent = f"agent-{marker}"
    alert_ids = [f"{marker}.{i}" for i in range(5)]
    lines = [_alert(agent, "9.9.9.9", aid) for aid in alert_ids]

    stop_flag, thread, metrics = _start_consumer(kafka_bootstrap, kafka_topic, database_url)
    try:
        _produce(kafka_bootstrap, kafka_topic, lines, tenant_key=tenant)

        deadline = time.monotonic() + 20
        row = None
        while time.monotonic() < deadline:
            row = db.execute(
                select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
            ).mappings().first()
            if row is not None and row["alert_count"] == 5:
                break
            time.sleep(0.5)

        assert row is not None, "no incident appeared for the produced alerts"
        assert row["alert_count"] == 5
        assert metrics.snapshot().get("alerts_created", 0) >= 1
    finally:
        stop_flag.set()
        thread.join(timeout=5)


def test_a_permanently_malformed_alert_is_skipped_not_wedging_the_partition(kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db):
    """Regression test for a real bug found in Phase 5A VERIFY: a bad
    timestamp (produced by a script bug, but the consumer can't tell that
    from a genuinely corrupt upstream alert) used to be treated as a
    transient failure and never committed - wedging the partition in an
    infinite retry loop that blocked every alert behind it, forever. One
    bad alert followed by 3 good ones on the same partition/agent must
    not lose the 3 good ones."""
    tenant = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    marker = uuid.uuid4().hex[:8]
    agent = f"agent-{marker}"
    bad = _alert(agent, "9.9.9.9", f"{marker}.bad", timestamp="2026-10-04T05:00:118.000+0000")
    good = [_alert(agent, "9.9.9.9", f"{marker}.{i}") for i in range(3)]

    stop_flag, thread, metrics = _start_consumer(kafka_bootstrap, kafka_topic, database_url)
    try:
        _produce(kafka_bootstrap, kafka_topic, [bad] + good, tenant_key=tenant)

        deadline = time.monotonic() + 20
        row = None
        while time.monotonic() < deadline:
            row = db.execute(
                select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
            ).mappings().first()
            if row is not None and row["alert_count"] == 3:
                break
            time.sleep(0.5)

        assert row is not None, "the 3 good alerts after the bad one never got processed - partition is wedged"
        assert row["alert_count"] == 3
        assert metrics.snapshot().get("messages_failed", 0) >= 1
    finally:
        stop_flag.set()
        thread.join(timeout=5)


def test_bad_data_is_dead_lettered_not_silently_dropped(kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db, ch_client, lab_env):
    """No single event may stop the pipeline: both failure kinds this
    consumer treats as permanent (a normalize_alert failure - here a
    missing required field, since the real shipper already filters out
    unparseable JSON before anything reaches this topic - and a
    permanently malformed field caught as UnparseableEvent) must land in
    dead_letter_events, not just bump a counter - someone needs to be able
    to find and inspect what got dropped."""
    tenant = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    # A second, dedicated client for this test's own polling - ch_client
    # itself is handed to the background consumer thread below for its
    # dead-letter writes, and clickhouse_connect's HTTP client isn't
    # safe to query concurrently from two threads on the same session
    # (confirmed empirically: "Attempt to execute concurrent queries
    # within the same session").
    import clickhouse_connect
    poll_client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database=TEST_CLICKHOUSE_DB,
    )
    marker = uuid.uuid4().hex[:8]
    agent = f"agent-{marker}"
    missing_timestamp = json.loads(_alert(agent, "9.9.9.9", f"{marker}.missing-ts"))
    del missing_timestamp["timestamp"]
    missing_timestamp = json.dumps(missing_timestamp)
    bad_timestamp = _alert(agent, "9.9.9.9", f"{marker}.bad-ts", timestamp="2026-10-04T05:00:118.000+0000")
    good = _alert(agent, "9.9.9.9", f"{marker}.good")

    stop_flag, thread, metrics = _start_consumer(kafka_bootstrap, kafka_topic, database_url, ch_client=ch_client)
    try:
        _produce(kafka_bootstrap, kafka_topic, [missing_timestamp, bad_timestamp, good], tenant_key=tenant)

        deadline = time.monotonic() + 20
        row = None
        while time.monotonic() < deadline:
            row = db.execute(
                select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
            ).mappings().first()
            if row is not None and row["alert_count"] == 1:
                break
            time.sleep(0.5)
        assert row is not None and row["alert_count"] == 1, "the good alert must still land"

        deadline = time.monotonic() + 15
        dl_count = 0
        while time.monotonic() < deadline:
            dl_count = poll_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant}' AND component = 'correlator'"
            ).result_rows[0][0]
            if dl_count == 2:
                break
            time.sleep(0.5)
        assert dl_count == 2, f"expected 2 dead-lettered events (missing timestamp + unparseable timestamp), got {dl_count}"
        assert thread.is_alive(), "correlator must never crash on bad data"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        poll_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant}'")
        poll_client.close()


def test_killing_a_worker_mid_attack_the_incident_survives_and_keeps_growing(kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db):
    """Kills the consumer mid-stream (not a graceful stop_flag) and starts
    a fresh one in a new consumer group reading from the beginning - the
    open incident must keep accumulating the same incident_id, never
    split into two, since all state lives in Postgres, not the worker's
    memory."""
    tenant = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    marker = uuid.uuid4().hex[:8]
    agent = f"agent-{marker}"
    group_id = f"test-correlate-kill-{marker}"

    first_half = [_alert(agent, "8.8.8.8", f"{marker}.a{i}") for i in range(3)]
    second_half = [_alert(agent, "8.8.8.8", f"{marker}.b{i}") for i in range(3)]

    stop_flag1, thread1, _ = _start_consumer(kafka_bootstrap, kafka_topic, database_url, group_id=group_id)
    _produce(kafka_bootstrap, kafka_topic, first_half, tenant_key=tenant)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        row = db.execute(
            select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
        ).mappings().first()
        if row is not None and row["alert_count"] == 3:
            break
        time.sleep(0.3)
    assert row is not None and row["alert_count"] == 3
    incident_id = row["id"]

    # Not stop_flag.set() + join - simulate a hard kill by just abandoning
    # the thread (daemon=True) without a graceful shutdown, same as a
    # process crash would leave Kafka's consumer group state.
    del thread1
    del stop_flag1

    stop_flag2, thread2, _ = _start_consumer(kafka_bootstrap, kafka_topic, database_url, group_id=group_id)
    try:
        _produce(kafka_bootstrap, kafka_topic, second_half, tenant_key=tenant)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            row = db.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().one()
            if row["alert_count"] == 6:
                break
            time.sleep(0.3)
        assert row["alert_count"] == 6, "the incident should keep growing, not split"

        same_incident = db.execute(
            select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
        ).mappings().all()
        assert len(same_incident) == 1, "must still be exactly one incident for this agent, not two"
    finally:
        stop_flag2.set()
        thread2.join(timeout=5)


def test_replaying_a_kafka_range_does_not_duplicate_membership_or_change_counts(kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db):
    tenant = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    marker = uuid.uuid4().hex[:8]
    agent = f"agent-{marker}"
    group_id = f"test-correlate-replay-{marker}"
    alert_ids = [f"{marker}.{i}" for i in range(4)]
    lines = [_alert(agent, "1.2.3.4", aid) for aid in alert_ids]

    stop_flag, thread, _ = _start_consumer(kafka_bootstrap, kafka_topic, database_url, group_id=group_id)
    _produce(kafka_bootstrap, kafka_topic, lines, tenant_key=tenant)
    deadline = time.monotonic() + 15
    row = None
    while time.monotonic() < deadline:
        row = db.execute(
            select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
        ).mappings().first()
        if row is not None and row["alert_count"] == 4:
            break
        time.sleep(0.3)
    assert row is not None and row["alert_count"] == 4
    incident_id = row["id"]
    stop_flag.set()
    thread.join(timeout=5)

    subprocess.run(
        ["docker", "exec", "shadowtracer-lab-kafka-1", "/opt/kafka/bin/kafka-consumer-groups.sh",
         "--bootstrap-server", "localhost:9092", "--command-config", "/etc/kafka/certs/admin-client.properties",
         "--group", group_id, "--topic", kafka_topic,
         "--reset-offsets", "--to-earliest", "--execute"],
        check=True, capture_output=True,
    )

    stop_flag2, thread2, _ = _start_consumer(kafka_bootstrap, kafka_topic, database_url, group_id=group_id)
    try:
        time.sleep(8)  # let the full replay drain
        row = db.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().one()
        assert row["alert_count"] == 4, "replay must not double-count"

        memberships = db.execute(
            select(incident_alerts).where(incident_alerts.c.incident_id == incident_id)
        ).mappings().all()
        assert len(memberships) == 4, "replay must not create duplicate membership rows"
    finally:
        stop_flag2.set()
        thread2.join(timeout=5)


def test_two_correlation_workers_split_partitions_nothing_processed_twice(kafka_bootstrap, database_url, db):
    """A multi-partition topic (unlike the single-partition kafka_topic
    fixture used elsewhere) with 2 consumers in the same group - Kafka
    assigns each worker a disjoint set of partitions, same as the real
    lab's writer-1/writer-2 split of the 24-partition events topic."""
    from confluent_kafka.admin import AdminClient, NewTopic

    # Phase 5.6 Item 1: a real per-tenant topic name now (not an
    # arbitrary "multipart" name) - writer.py/consumer.py only ever
    # pattern-subscribe to shadowtracer.t.*.alerts.
    tenant = f"test-{uuid.uuid4().hex[:8]}"  # "test-": the only topics test consumers subscribe to
    insert_tenant(db, tenant)
    topic = alerts_topic_for_tenant(tenant)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    admin.create_topics([NewTopic(topic, num_partitions=4, replication_factor=1)])
    time.sleep(1)

    marker = uuid.uuid4().hex[:8]
    group_id = f"test-correlate-split-{marker}"
    n_agents = 8
    alerts_per_agent = 3
    lines = []
    for a in range(n_agents):
        agent = f"agent-{marker}-{a}"
        for i in range(alerts_per_agent):
            lines.append(_alert(agent, f"5.5.5.{a}", f"{marker}.{a}.{i}"))

    # This topic only: other tests creating/deleting test- topics would
    # otherwise trigger rebalances mid-test (one worker briefly owning all).
    only_this = "^" + re.escape(topic) + "$"
    stop_flag1, thread1, metrics1 = _start_consumer(kafka_bootstrap, topic, database_url, group_id=group_id, topic_pattern=only_this)
    stop_flag2, thread2, metrics2 = _start_consumer(kafka_bootstrap, topic, database_url, group_id=group_id, topic_pattern=only_this)
    try:
        # started_flag only means subscribe() was called, not that the group's
        # rebalance has settled. A batching worker that is alone even briefly
        # takes every message in one consume(), so wait until the group really
        # has both members, each owning partitions of this topic.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            members = admin.describe_consumer_groups([group_id])[group_id].result(timeout=10).members
            owned = [m for m in members
                     if m.assignment and any(tp.topic == topic for tp in m.assignment.topic_partitions)]
            if len(owned) == 2:
                break
            time.sleep(1)
        assert len(owned) == 2, f"both workers must own partitions before producing ({len(owned)} do)"
        _produce(kafka_bootstrap, topic, lines, tenant_key=tenant)

        deadline = time.monotonic() + 20
        rows = []
        while time.monotonic() < deadline:
            rows = db.execute(select(incidents).where(incidents.c.tenant_key == tenant)).mappings().all()
            total = sum(r["alert_count"] for r in rows)
            if total == n_agents * alerts_per_agent:
                break
            time.sleep(0.5)

        assert len(rows) == n_agents, "one incident per agent"
        assert all(r["alert_count"] == alerts_per_agent for r in rows), "no alert processed twice, none missing"

        both_did_work = metrics1.snapshot().get("alerts_created", 0) > 0 and metrics2.snapshot().get("alerts_created", 0) > 0
        assert both_did_work, "both workers should have owned at least one partition with data"
    finally:
        stop_flag1.set()
        stop_flag2.set()
        thread1.join(timeout=5)
        thread2.join(timeout=5)
        delete_topics_and_wait(admin, [topic])


def _drain_dead_letter_topic(kafka_bootstrap, tenant_key, expected_marker, timeout=15):
    consumer = Consumer({
        "bootstrap.servers": kafka_bootstrap,
        "group.id": f"test-dlt-drain-{uuid.uuid4().hex[:8]}",
        "auto.offset.reset": "earliest",
        **kafka_client_config_from_env(),
    })
    consumer.subscribe([dead_letter_topic_for_tenant(tenant_key)])
    deadline = time.monotonic() + timeout
    found = None
    while time.monotonic() < deadline:
        msg = consumer.poll(1.0)
        if msg is not None and msg.error() is None and expected_marker in msg.value().decode():
            found = msg.value().decode()
            break
    consumer.close()
    return found


def test_correlator_stays_up_when_dead_letter_clickhouse_insert_fails(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db, ch_client,
):
    """Dead-letter-ClickHouse incident (2026-10-08) hardening, at the real
    consumer.run() level: the dead_letter_events table itself is
    unreachable (a real, atomic RENAME TABLE - never the Keeper surgery
    that caused the real incident - restored in `finally`), while every
    other table, including incidents/incident_alerts in Postgres and the
    correlator's own main code path, stays healthy. A permanently
    malformed alert must still not crash the correlator, must still land
    on the Kafka dead-letter topic (published before the ClickHouse
    attempt - see dead_letter.py), and must count dead_letter_ch_failures
    - and the good alert right behind it on the same partition must still
    process, proving the partition isn't wedged by this either."""
    tenant = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    marker = uuid.uuid4().hex[:8]
    agent = f"agent-{marker}"
    bad_timestamp = _alert(agent, "9.9.9.9", f"{marker}.bad-ts", timestamp="2026-10-04T05:00:118.000+0000")
    good = _alert(agent, "9.9.9.9", f"{marker}.good")

    tmp_name = f"dead_letter_events_tmp_{marker}"
    ch_client.command(
        f"RENAME TABLE {TEST_CLICKHOUSE_DB}.dead_letter_events TO {TEST_CLICKHOUSE_DB}.{tmp_name} ON CLUSTER lab_cluster"
    )
    try:
        stop_flag, thread, metrics = _start_consumer(kafka_bootstrap, kafka_topic, database_url, ch_client=ch_client)
        try:
            _produce(kafka_bootstrap, kafka_topic, [bad_timestamp, good], tenant_key=tenant)

            deadline = time.monotonic() + 20
            row = None
            while time.monotonic() < deadline:
                row = db.execute(
                    select(incidents).where(incidents.c.tenant_key == tenant, incidents.c.agent_id == agent)
                ).mappings().first()
                if row is not None and row["alert_count"] == 1:
                    break
                time.sleep(0.5)
            assert row is not None and row["alert_count"] == 1, (
                "the good alert right behind the dead-lettered one must still land - "
                "the ClickHouse-side failure must not wedge the partition"
            )

            assert thread.is_alive(), "correlator must never crash when the dead-letter ClickHouse insert fails"
            found = _drain_dead_letter_topic(kafka_bootstrap, tenant, f"{marker}.bad-ts")
            assert found is not None, "the Kafka dead-letter topic copy must still land even when ClickHouse fails"
            assert metrics.snapshot().get("dead_letter_ch_failures", 0) >= 1
        finally:
            stop_flag.set()
            thread.join(timeout=5)
    finally:
        ch_client.command(
            f"RENAME TABLE {TEST_CLICKHOUSE_DB}.{tmp_name} TO {TEST_CLICKHOUSE_DB}.dead_letter_events ON CLUSTER lab_cluster"
        )


def test_correlator_dead_letters_unknown_tenant_known_tenant_still_processes(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db, ch_client, lab_env,
):
    """Phase 5C Step 0: a tenant_key with no backing tenants row must be
    dead-lettered (error="unknown_tenant"), never create an incident -
    proven alongside kafka_topic's own real, flagged-as-test tenant
    whose otherwise-identical alert still lands normally, so this isn't
    just "the correlator dead-letters everything right now".

    Phase 5.6 Item 1: "unknown tenant" needs its own topic (a real
    producer ACL was granted for it) with no matching tenants row -
    kafka_topic's own topic always has one by construction."""
    import clickhouse_connect
    from confluent_kafka.admin import AdminClient, NewTopic

    known_tenant = kafka_tenant_key
    unknown_tenant = f"test-unknown-{uuid.uuid4().hex[:8]}"  # topic provisioned below, deliberately never inserted into tenants
    unknown_topic = alerts_topic_for_tenant(unknown_tenant)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    # Both topics, as create-kafka-topics.sh provisions them: the tenant row is
    # what's missing here, not its topics (an offboarded tenant whose topics
    # are gone too is test_offboarded_tenant_message_does_not_stall_other_tenants).
    admin.create_topics([NewTopic(unknown_topic, num_partitions=1, replication_factor=1),
                         NewTopic(dead_letter_topic_for_tenant(unknown_tenant), num_partitions=1, replication_factor=1)])
    time.sleep(1)
    marker = uuid.uuid4().hex[:8]
    known_agent = f"agent-known-{marker}"
    unknown_agent = f"agent-unknown-{marker}"

    # A separate client from the one handed to the consumer thread below -
    # clickhouse_connect's HTTP client tracks an active session internally
    # and raises "concurrent queries within the same session" if the same
    # client object is used from two threads at once (found the hard way
    # writing this test): this test's own polling loop must never share
    # the consumer's client.
    poll_client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123, username=lab_env["CLICKHOUSE_USER"],
        password=lab_env["CLICKHOUSE_PASSWORD"], database=TEST_CLICKHOUSE_DB,
    )

    stop_flag, thread, metrics = _start_consumer(kafka_bootstrap, kafka_topic, database_url, ch_client=ch_client)
    try:
        _produce(kafka_bootstrap, kafka_topic, [_alert(known_agent, "9.9.9.9", f"{marker}.known")], tenant_key=known_tenant)
        _produce(kafka_bootstrap, unknown_topic, [_alert(unknown_agent, "9.9.9.9", f"{marker}.unknown")], tenant_key=unknown_tenant)

        deadline = time.monotonic() + 20
        row = dl_count = None
        while time.monotonic() < deadline:
            row = db.execute(
                select(incidents).where(incidents.c.tenant_key == known_tenant, incidents.c.agent_id == known_agent)
            ).mappings().first()
            dl_count = poll_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{unknown_tenant}' AND error = 'unknown_tenant'"
            ).result_rows[0][0]
            if row is not None and row["alert_count"] == 1 and dl_count == 1:
                break
            time.sleep(0.5)

        assert row is not None and row["alert_count"] == 1, "the known (flagged-test) tenant's alert must still create an incident"
        assert dl_count == 1, "the unknown tenant's alert must be dead-lettered with error=unknown_tenant"
        unknown_row = db.execute(
            select(incidents).where(incidents.c.tenant_key == unknown_tenant)
        ).mappings().first()
        assert unknown_row is None, "the unknown tenant's alert must never create an incident"
        assert thread.is_alive(), "correlator must never crash on an unknown tenant"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        poll_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{unknown_tenant}'")
        poll_client.close()
        # The dead-letter topic was never explicitly created above, but
        # the correlator's own dead-letter produce for the unknown-tenant
        # event brings it into existence anyway - confirmed left behind
        # every run until this was added (same gap as writer.py's own
        # equivalent test).
        delete_topics_and_wait(admin, [unknown_topic, dead_letter_topic_for_tenant(unknown_tenant)])


def test_correlator_dead_letters_unsupported_envelope_version_known_version_still_processes(
    kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db, ch_client, lab_env,
):
    """Phase 5.6 Item 4: an envelope_version header this correlator doesn't
    recognize must be dead-lettered (error starts "unsupported_envelope_
    version"), never create an incident - same shape as the unknown_tenant
    test above."""
    import clickhouse_connect
    from shadowtracer_correlate.consumer import ENVELOPE_VERSION

    tenant_key = kafka_tenant_key  # Phase 5.6 Item 1: kafka_topic's own tenant, not a separate one
    marker = uuid.uuid4().hex[:8]
    known_agent = f"agent-known-{marker}"
    future_agent = f"agent-future-{marker}"

    poll_client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123, username=lab_env["CLICKHOUSE_USER"],
        password=lab_env["CLICKHOUSE_PASSWORD"], database=TEST_CLICKHOUSE_DB,
    )

    stop_flag, thread, metrics = _start_consumer(kafka_bootstrap, kafka_topic, database_url, ch_client=ch_client)
    try:
        producer = Producer({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
        producer.produce(
            kafka_topic, value=_alert(known_agent, "9.9.9.9", f"{marker}.known").encode(),
            key=known_agent.encode(),
            headers=[
                ("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json"),
                ("envelope_version", str(ENVELOPE_VERSION).encode()),
            ],
        )
        producer.produce(
            kafka_topic, value=_alert(future_agent, "9.9.9.9", f"{marker}.future").encode(),
            key=future_agent.encode(),
            headers=[
                ("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json"),
                ("envelope_version", b"99"),
            ],
        )
        producer.flush(30)

        # 40s, not 20s - group-join latency under a busy shared test cluster;
        # see test_writer.py's test_writer_is_actually_running_and_draining_
        # not_just_callable's comment on this exact margin.
        deadline = time.monotonic() + 40
        row = dl_count = None
        while time.monotonic() < deadline:
            row = db.execute(
                select(incidents).where(incidents.c.tenant_key == tenant_key, incidents.c.agent_id == known_agent)
            ).mappings().first()
            dl_count = poll_client.query(
                f"SELECT count() FROM dead_letter_events WHERE tenant_id = '{tenant_key}' "
                f"AND error LIKE 'unsupported_envelope_version%'"
            ).result_rows[0][0]
            if row is not None and row["alert_count"] == 1 and dl_count == 1:
                break
            time.sleep(0.5)

        assert row is not None and row["alert_count"] == 1, "the event at the real ENVELOPE_VERSION must still create an incident"
        assert dl_count == 1, "the unsupported-version alert must be dead-lettered with error=unsupported_envelope_version..."
        future_row = db.execute(
            select(incidents).where(incidents.c.tenant_key == tenant_key, incidents.c.agent_id == future_agent)
        ).mappings().first()
        assert future_row is None, "the unsupported-version alert must never create an incident"
        assert thread.is_alive(), "correlator must never crash on an unsupported envelope version"
    finally:
        stop_flag.set()
        thread.join(timeout=5)
        poll_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{tenant_key}'")
        poll_client.close()


def test_offboarded_tenant_message_does_not_stall_other_tenants(kafka_bootstrap, kafka_topic, kafka_tenant_key, database_url, db, ch_client):
    """Tenant offboarding (docs/design/TENANCY.md §6), correlator side: a
    message left in an offboarded tenant's alerts topic (tenants row gone,
    dead-letter topic deleted) is recorded in ClickHouse and skipped; the
    other tenant's alerts still become incidents."""
    from confluent_kafka.admin import AdminClient, NewTopic

    marker = uuid.uuid4().hex[:8]
    offboarded = f"test-off-{marker}"
    off_topic = alerts_topic_for_tenant(offboarded)
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap, **kafka_client_config_from_env()})
    admin.create_topics([NewTopic(off_topic, num_partitions=1, replication_factor=1)])[off_topic].result(30)
    agent = f"agent-{marker}"
    try:
        _produce(kafka_bootstrap, off_topic, [_alert(agent, "7.7.7.7", f"{marker}.off")], tenant_key=offboarded)
        stop_flag, thread, metrics = _start_consumer(
            kafka_bootstrap, kafka_topic, database_url, ch_client=ch_client,
            kafka_config_extra={"allow.auto.create.topics": False},  # as the lab's correlator principal
        )
        try:
            time.sleep(3)
            _produce(kafka_bootstrap, kafka_topic, [_alert(agent, "7.7.7.7", f"{marker}.{i}") for i in range(3)],
                     tenant_key=kafka_tenant_key)
            deadline = time.monotonic() + 60
            row = None
            while time.monotonic() < deadline:
                row = db.execute(select(incidents).where(incidents.c.tenant_key == kafka_tenant_key,
                                                         incidents.c.agent_id == agent)).mappings().first()
                if row is not None and row["alert_count"] == 3:
                    break
                time.sleep(0.5)
        finally:
            stop_flag.set()
            thread.join(timeout=10)
        assert row is not None and row["alert_count"] == 3, "the other tenant's alerts must keep correlating"
        rows = ch_client.query("SELECT error FROM dead_letter_events WHERE tenant_id = {t:String}",
                               parameters={"t": offboarded}).result_rows
        assert rows and "tenant offboarded" in rows[0][0], rows
        assert metrics.snapshot().get("dead_letter_topic_missing", 0) >= 1
    finally:
        delete_topics_and_wait(admin, [off_topic])
        ch_client.command(f"ALTER TABLE dead_letter_events DELETE WHERE tenant_id = '{offboarded}'")
