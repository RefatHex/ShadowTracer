import datetime
import threading
import time
import uuid

from sqlalchemy import select

from conftest import TEST_CLICKHOUSE_DB, insert_tenant
from shadowtracer_correlate.closer import close_eligible_incidents
from shadowtracer_correlate.closer_loop import run as run_closer_loop
from shadowtracer_correlate.metrics import Metrics
from shadowtracer_correlate.models import fingerprints, incidents

INTERNAL_RANGES = ["10.0.0.0/8"]


def _insert_quiet_incident(db, tenant, agent, last_seen_ago_seconds, rule_groups=None, alert_count=10):
    now = datetime.datetime.now(datetime.timezone.utc)
    last_seen = now - datetime.timedelta(seconds=last_seen_ago_seconds)
    result = db.execute(
        incidents.insert().values(
            tenant_key=tenant, correlation_key=f"{agent}|srcip:8.8.8.8", correlation_basis="source_ip",
            agent_id=agent, first_seen=last_seen - datetime.timedelta(minutes=2), last_seen=last_seen,
            alert_count=alert_count, max_level=5,
            rule_ids=["5710"], rule_groups=rule_groups or ["sshd"], mitre_ids=["T1110.001"],
            source_ips=["8.8.8.8"], source_ip_total=1, users=[], user_total=0,
        ).returning(incidents.c.id)
    )
    db.commit()
    return result.scalar_one()


def test_quiet_incident_past_session_gap_gets_closed_with_a_fingerprint(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    incident_id = _insert_quiet_incident(db, tenant, "agent-a", last_seen_ago_seconds=700)

    closed = close_eligible_incidents(db, ch_client, TEST_CLICKHOUSE_DB, session_gap_seconds=600, internal_ranges=INTERNAL_RANGES)

    assert incident_id in closed
    row = db.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().one()
    assert row["state"] == "closed"
    assert row["fingerprint_key"] is not None
    assert row["closed_at"] is not None

    fp_row = db.execute(
        select(fingerprints).where(fingerprints.c.tenant_key == tenant, fingerprints.c.fingerprint_key == row["fingerprint_key"])
    ).mappings().first()
    assert fp_row is not None

    occurrence_count = ch_client.query(
        "SELECT uniqExact(incident_id) FROM fingerprint_occurrences WHERE tenant_id = {t:String} AND fingerprint_key = {f:String}",
        parameters={"t": tenant, "f": row["fingerprint_key"]},
    ).result_rows[0][0]
    assert occurrence_count == 1


def test_incident_within_session_gap_is_not_closed(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    incident_id = _insert_quiet_incident(db, tenant, "agent-b", last_seen_ago_seconds=30)

    closed = close_eligible_incidents(db, ch_client, TEST_CLICKHOUSE_DB, session_gap_seconds=600, internal_ranges=INTERNAL_RANGES)

    assert incident_id not in closed
    row = db.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().one()
    assert row["state"] == "open"


def test_same_attack_two_source_ips_two_incidents_one_fingerprint(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    id1 = _insert_quiet_incident(db, tenant, "agent-c", last_seen_ago_seconds=700)
    id2 = _insert_quiet_incident(db, tenant, "agent-c", last_seen_ago_seconds=700)
    # Give them different source IPs directly (simulating two separate
    # source_ip-basis incidents against the same agent).
    db.execute(incidents.update().where(incidents.c.id == id2).values(source_ips=["1.1.1.1"]))
    db.commit()

    closed = close_eligible_incidents(db, ch_client, TEST_CLICKHOUSE_DB, session_gap_seconds=600, internal_ranges=INTERNAL_RANGES)
    assert set(closed) >= {id1, id2}

    rows = db.execute(select(incidents).where(incidents.c.id.in_([id1, id2]))).mappings().all()
    fingerprint_keys = {r["fingerprint_key"] for r in rows}
    assert len(fingerprint_keys) == 1, "same shape (only differing by IP, which isn't hashed) must be one fingerprint"

    occurrence_count = ch_client.query(
        "SELECT uniqExact(incident_id) FROM fingerprint_occurrences WHERE tenant_id = {t:String} AND fingerprint_key = {f:String}",
        parameters={"t": tenant, "f": fingerprint_keys.pop()},
    ).result_rows[0][0]
    assert occurrence_count == 2


def test_a_different_attack_gets_a_different_fingerprint(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    ssh_id = _insert_quiet_incident(db, tenant, "agent-d", last_seen_ago_seconds=700, rule_groups=["sshd", "authentication_failed"])
    local_user_id = _insert_quiet_incident(db, tenant, "agent-e", last_seen_ago_seconds=700, rule_groups=["authentication", "syscheck"])
    db.execute(incidents.update().where(incidents.c.id == local_user_id).values(source_ips=[], mitre_ids=["T1136.001"]))
    db.commit()

    close_eligible_incidents(db, ch_client, TEST_CLICKHOUSE_DB, session_gap_seconds=600, internal_ranges=INTERNAL_RANGES)

    rows = db.execute(select(incidents).where(incidents.c.id.in_([ssh_id, local_user_id]))).mappings().all()
    fingerprint_keys = {r["fingerprint_key"] for r in rows}
    assert len(fingerprint_keys) == 2


def test_two_closer_replicas_never_close_the_same_incident_twice(db, ch_client, lab_env, database_url):
    """Simulates 2 closer replicas racing the same candidate incident -
    each gets its OWN db session/connection (a real second connection,
    not a shared one, since the advisory lock is connection/transaction
    scoped) and runs concurrently in a thread."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import clickhouse_connect

    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    incident_id = _insert_quiet_incident(db, tenant, "agent-race", last_seen_ago_seconds=700)

    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    results = {}

    def close_with_own_connection(worker_name):
        worker_db = Session()
        worker_ch = clickhouse_connect.get_client(
            host="127.0.0.1", port=8123,
            username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
            database=TEST_CLICKHOUSE_DB,
        )
        try:
            results[worker_name] = close_eligible_incidents(
                worker_db, worker_ch, TEST_CLICKHOUSE_DB, session_gap_seconds=600, internal_ranges=INTERNAL_RANGES,
            )
        finally:
            worker_ch.close()
            worker_db.close()

    t1 = threading.Thread(target=close_with_own_connection, args=("w1",))
    t2 = threading.Thread(target=close_with_own_connection, args=("w2",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    both_closed_it = incident_id in results["w1"] and incident_id in results["w2"]
    assert not both_closed_it, "exactly one replica should have closed this incident, not both"

    occurrence_count = ch_client.query(
        "SELECT uniqExact(incident_id) FROM fingerprint_occurrences WHERE incident_id = {i:UInt64}",
        parameters={"i": incident_id},
    ).result_rows[0][0]
    assert occurrence_count == 1, "even if both raced, the occurrence history must show exactly one closure"


def test_closer_loop_is_actually_running_and_draining_not_just_callable(db, ch_client, lab_env, database_url):
    """Proves the closer's main loop is live: we never call
    close_eligible_incidents directly here - we only start closer_loop.run()
    in a thread and insert a quiet incident, exactly like a real
    deployment would."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    incident_id = _insert_quiet_incident(db, tenant, "agent-loop", last_seen_ago_seconds=700)

    metrics = Metrics()
    stop_flag = threading.Event()
    started_flag = threading.Event()
    thread = threading.Thread(
        target=run_closer_loop,
        kwargs=dict(
            database_url=database_url,
            clickhouse_host="127.0.0.1", clickhouse_port=8123,
            clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
            clickhouse_database=TEST_CLICKHOUSE_DB,
            session_gap_seconds=600, internal_ranges=INTERNAL_RANGES,
            metrics=metrics, stop_flag=stop_flag, poll_interval_seconds=1,
            started_flag=started_flag,
        ),
        daemon=True,
    )
    thread.start()
    try:
        assert started_flag.wait(timeout=10)
        deadline = time.monotonic() + 15
        row = None
        while time.monotonic() < deadline:
            row = db.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().one()
            if row["state"] == "closed":
                break
            time.sleep(0.5)
        assert row["state"] == "closed"
        assert metrics.snapshot().get("incidents_closed", 0) >= 1
    finally:
        stop_flag.set()
        thread.join(timeout=5)
