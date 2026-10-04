import json
import subprocess
import threading
import time
import uuid

from confluent_kafka import Producer
from sqlalchemy import select

from shadowtracer_correlate.consumer import run
from shadowtracer_correlate.metrics import Metrics
from shadowtracer_correlate.models import incident_alerts, incidents


def _alert(agent_id: str, src_ip: str, alert_id: str) -> str:
    return json.dumps({
        "timestamp": "2026-01-01T12:00:00.000+0000",
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


def _produce(kafka_bootstrap, topic, lines, tenant_key="lab"):
    """Keys each message by tenant:agent, exactly like the real shipper
    (shipper.py) - this is what actually guarantees one agent's events
    all land on the same partition, owned by exactly one worker. A test
    that produced without this key would let two different workers
    legitimately race on the same agent, which can't happen for real."""
    producer = Producer({"bootstrap.servers": kafka_bootstrap})
    for line in lines:
        agent_id = json.loads(line)["agent"]["id"]
        producer.produce(
            topic, value=line.encode(), key=f"{tenant_key}:{agent_id}".encode(),
            headers=[("tenant_id", tenant_key.encode()), ("source_manager", b"test"), ("source_file", b"alerts.json")],
        )
    producer.flush(30)


def _start_consumer(kafka_bootstrap, topic, database_url, group_id=None):
    metrics = Metrics()
    stop_flag = threading.Event()
    started_flag = threading.Event()
    thread = threading.Thread(
        target=run,
        kwargs=dict(
            bootstrap_servers=kafka_bootstrap, topic=topic,
            group_id=group_id or f"test-correlate-{uuid.uuid4().hex[:8]}",
            database_url=database_url, metrics=metrics,
            stop_flag=stop_flag, started_flag=started_flag,
        ),
        daemon=True,
    )
    thread.start()
    assert started_flag.wait(timeout=10), "consumer never signalled started"
    return stop_flag, thread, metrics


def test_correlator_is_actually_running_and_draining_not_just_callable(kafka_bootstrap, kafka_topic, database_url, db):
    """Proves the consumer's main loop is live: we never call process_event
    directly here - we only start consumer.run() in a thread and produce
    to Kafka, exactly like a real deployment would."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
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


def test_killing_a_worker_mid_attack_the_incident_survives_and_keeps_growing(kafka_bootstrap, kafka_topic, database_url, db):
    """Kills the consumer mid-stream (not a graceful stop_flag) and starts
    a fresh one in a new consumer group reading from the beginning - the
    open incident must keep accumulating the same incident_id, never
    split into two, since all state lives in Postgres, not the worker's
    memory."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
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


def test_replaying_a_kafka_range_does_not_duplicate_membership_or_change_counts(kafka_bootstrap, kafka_topic, database_url, db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
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
         "--bootstrap-server", "localhost:9092", "--group", group_id, "--topic", kafka_topic,
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

    topic = f"shadowtracer.test.multipart.{uuid.uuid4().hex[:8]}"
    admin = AdminClient({"bootstrap.servers": kafka_bootstrap})
    admin.create_topics([NewTopic(topic, num_partitions=4, replication_factor=1)])
    time.sleep(1)

    tenant = f"t-{uuid.uuid4().hex[:8]}"
    marker = uuid.uuid4().hex[:8]
    group_id = f"test-correlate-split-{marker}"
    n_agents = 8
    alerts_per_agent = 3
    lines = []
    for a in range(n_agents):
        agent = f"agent-{marker}-{a}"
        for i in range(alerts_per_agent):
            lines.append(_alert(agent, f"5.5.5.{a}", f"{marker}.{a}.{i}"))

    stop_flag1, thread1, metrics1 = _start_consumer(kafka_bootstrap, topic, database_url, group_id=group_id)
    stop_flag2, thread2, metrics2 = _start_consumer(kafka_bootstrap, topic, database_url, group_id=group_id)
    try:
        # started_flag only means subscribe() was called, not that the
        # group's rebalance has settled with both members - give it a
        # moment, or one worker can grab every partition before the
        # second one finishes joining the generation.
        time.sleep(5)
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
        admin.delete_topics([topic])
