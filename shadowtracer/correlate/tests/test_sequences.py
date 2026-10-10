"""Phase 5B Step 4: sequence detection. Real PostgreSQL (sequence_progress)
and real ClickHouse (sequence_firings) - no mocks. Drives the real
process_event (not evaluate_sequences directly), so this exercises the
exact same code path the real correlator runs."""

import datetime
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))
from shadowtracer_ingest.normalizer import NormalizedEvent  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shadowtracer_correlate.correlator import process_event  # noqa: E402
from shadowtracer_correlate.sequences import load_sequences  # noqa: E402

from conftest import TEST_CLICKHOUSE_DB as TEST_CH_DB, insert_tenant  # noqa: E402

SEQUENCES_DIR = os.path.join(os.path.dirname(__file__), "..", "sequences")
SEQUENCES = load_sequences(SEQUENCES_DIR)
BRUTE_FORCE_SEQ_ID = "ssh_brute_force_then_success"


def _event(
    tenant="lab", agent_id="agent-1", alert_id=None, time=None,
    src_ip="9.9.9.9", user="", rule_groups=None, cluster_node="worker1",
) -> NormalizedEvent:
    return NormalizedEvent(
        tenant_id=tenant,
        time=(time or datetime.datetime.now(datetime.timezone.utc)).isoformat(),
        cluster_node=cluster_node,
        manager_name="wazuh-worker1",
        alert_id=alert_id or uuid.uuid4().hex,
        agent_id=agent_id,
        agent_name=agent_id,
        agent_ip="10.0.0.1",
        rule_id="5710",
        rule_level=5,
        rule_description="test rule",
        rule_groups=rule_groups or [],
        mitre_ids=[],
        mitre_tactics=[],
        mitre_techniques=[],
        src_endpoint_ip=src_ip,
        src_endpoint_port=0,
        dst_endpoint_ip="",
        dst_endpoint_port=0,
        actor_user=user,
        target_user="",
        decoder_name="sshd",
        location="/var/log/auth.log",
        message="test",
        extra_fields={},
        raw_event="{}",
    )


def _process(db, ch_client, event):
    return process_event(
        db, event, session_gap_seconds=600, max_span_seconds=14400,
        sequences=SEQUENCES, ch_client=ch_client, clickhouse_database=TEST_CH_DB,
    )


def _firing_count(ch_client, tenant, sequence_id):
    return ch_client.query(
        "SELECT uniqExact(completing_alert_id) FROM sequence_firings "
        "WHERE tenant_id = {tenant:String} AND sequence_id = {sequence_id:String}",
        parameters={"tenant": tenant, "sequence_id": sequence_id},
    ).result_rows[0][0]


def test_sequence_fires_once_for_a_real_two_step_pattern(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.50"
    now = datetime.datetime.now(datetime.timezone.utc)

    r1 = _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"], time=now,
    ))
    assert r1.status == "created"
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 0

    r2 = _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now + datetime.timedelta(seconds=30),
    ))
    assert r2.status == "joined"
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1

    row = ch_client.query(
        "SELECT step_matches FROM sequence_firings WHERE tenant_id = {t:String} AND sequence_id = {s:String}",
        parameters={"t": tenant, "s": BRUTE_FORCE_SEQ_ID},
    ).result_rows[0][0]
    assert "step_index" in row and "alert_id" in row  # "so the analyst can see why"


def test_replaying_the_completing_alert_does_not_fire_twice(db, ch_client):
    """Idempotent: replaying a Kafka range must not fire a sequence
    twice. Replays the EXACT SAME alert (same alert_id) that completed
    the sequence - process_event's own idempotency check must short-circuit
    before sequence evaluation ever runs a second time for it."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.51"
    now = datetime.datetime.now(datetime.timezone.utc)

    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"], time=now,
    ))
    completing_event = _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"], alert_id="replay-me",
        time=now + datetime.timedelta(seconds=30),
    )
    _process(db, ch_client, completing_event)
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1

    # Exact replay of the same completing alert.
    replay_result = _process(db, ch_client, completing_event)
    assert replay_result.status == "duplicate"
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1, "must still be exactly 1 firing after the replay"


def test_partial_sequence_does_not_fire(db, ch_client):
    """Only step 0 has matched - must not fire, no matter how long we wait
    (within this test's timeframe)."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.52"

    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"],
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 0


def test_out_of_order_step_does_not_fire(db, ch_client):
    """Step 1's alert arrives with NO step 0 ever having matched for this
    key - must not advance or fire. A later, correctly-ordered step 0
    then step 1 must still work normally afterward."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.53"
    now = datetime.datetime.now(datetime.timezone.utc)

    # Step 1 alert first, nothing has matched step 0 yet.
    r1 = _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"], time=now,
    ))
    assert r1.status == "created"
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 0, "a bare step-1 alert must never fire anything"

    # Now the real order: step 0 then step 1 - must complete normally.
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"],
        time=now + datetime.timedelta(seconds=10),
    ))
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now + datetime.timedelta(seconds=40),
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1


def test_sequence_window_expiry_prevents_firing_until_a_fresh_step_zero(db, ch_client):
    """window_seconds for ssh_brute_force_then_success is 600s. A step 1
    alert arriving AFTER that window from step 0 must not complete the
    stale attempt. A fresh step 0 + step 1 within a new window must then
    fire normally."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.54"
    now = datetime.datetime.now(datetime.timezone.utc)

    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"], time=now,
    ))
    # Step 1 arrives 700s later - past the 600s window.
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now + datetime.timedelta(seconds=700),
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 0, "expired partial sequence must not fire"

    # A fresh, correctly-timed attempt afterward must still work.
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"],
        time=now + datetime.timedelta(seconds=710),
    ))
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now + datetime.timedelta(seconds=730),
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1


def test_sequence_detection_is_per_tenant(db, ch_client):
    """Two different tenants, same agent id, same source IP, same real
    attack pattern - each tenant's firing count must reflect only its own
    activity."""
    tenant_a = f"t-a-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant_a)
    tenant_b = f"t-b-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant_b)
    agent = "agent-shared-name"
    ip = "203.0.113.55"
    now = datetime.datetime.now(datetime.timezone.utc)

    for tenant in (tenant_a, tenant_b):
        _process(db, ch_client, _event(
            tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"], time=now,
        ))

    # Only tenant A completes the sequence.
    _process(db, ch_client, _event(
        tenant=tenant_a, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now + datetime.timedelta(seconds=30),
    ))

    assert _firing_count(ch_client, tenant_a, BRUTE_FORCE_SEQ_ID) == 1
    assert _firing_count(ch_client, tenant_b, BRUTE_FORCE_SEQ_ID) == 0


def test_step1_chronologically_before_step0_by_more_than_lateness_does_not_fire(db, ch_client):
    """Phase 5C Step 0b: step 0 matches at t=now. A step-1-matching alert
    then arrives (in CONSUMPTION order) whose own alert_time is 60s
    BEFORE step 0's - well past the 30s default lateness window. This is
    the out-of-order-by-event-time case (e.g. the LB moved the agent to
    another worker and that worker's backlog is being replayed) - it
    must be a no-op, not a false completion. A correctly-ordered step 1
    afterward must still complete the sequence normally."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.56"
    now = datetime.datetime.now(datetime.timezone.utc)

    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"], time=now,
    ))

    # Matches step_groups[1], but its alert_time is 60s BEFORE step 0's -
    # out of order by event time, not just delayed in Kafka.
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now - datetime.timedelta(seconds=60),
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 0, \
        "an alert chronologically before the step it would complete must not fire anything"

    # The real, correctly-ordered step 1 still completes it afterward.
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now + datetime.timedelta(seconds=30),
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1, \
        "the genuinely-ordered completion must still fire after the rejected one"


def test_step1_within_lateness_window_still_fires(db, ch_client):
    """A step-1 alert whose alert_time is slightly BEFORE step 0's - but
    within the 30s default lateness window (clock-skew/jitter tolerance,
    not a real ordering violation) - must still complete the sequence."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.57"
    now = datetime.datetime.now(datetime.timezone.utc)

    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_failed"], time=now,
    ))
    _process(db, ch_client, _event(
        tenant=tenant, agent_id=agent, src_ip=ip, rule_groups=["authentication_success"],
        time=now - datetime.timedelta(seconds=10),  # within the 30s lateness tolerance
    ))
    assert _firing_count(ch_client, tenant, BRUTE_FORCE_SEQ_ID) == 1, \
        "within the lateness window - must still be treated as completing the sequence"
