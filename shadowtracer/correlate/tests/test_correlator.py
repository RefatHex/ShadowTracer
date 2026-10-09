import datetime
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))
from shadowtracer_ingest.normalizer import NormalizedEvent  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shadowtracer_correlate import correlator  # noqa: E402
from shadowtracer_correlate.correlator import (  # noqa: E402
    correlation_key_and_basis, process_event,
)

from conftest import insert_tenant  # noqa: E402
from shadowtracer_correlate.models import incident_alerts, incidents  # noqa: E402

from sqlalchemy import select  # noqa: E402


def _event(
    tenant="lab", agent_id="agent-1", alert_id=None, time=None,
    src_ip="", user="", rule_groups=None, rule_id="5710", rule_level=5,
    mitre_ids=None, cluster_node="worker1",
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
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description="test rule",
        rule_groups=rule_groups or [],
        mitre_ids=mitre_ids or [],
        mitre_tactics=[],
        mitre_techniques=[],
        src_endpoint_ip=src_ip,
        src_endpoint_port=0,
        dst_endpoint_ip="",
        dst_endpoint_port=0,
        actor_user=user,
        target_user="",
        decoder_name="test",
        location="test",
        message="test message",
        extra_fields={},
        raw_event="{}",
    )


def test_correlation_key_priority_source_ip_first():
    ev = _event(src_ip="1.2.3.4", user="bob", rule_groups=["sshd"])
    key, basis = correlation_key_and_basis(ev)
    assert basis == "source_ip"
    assert "1.2.3.4" in key


def test_correlation_key_priority_user_when_no_ip():
    ev = _event(src_ip="", user="bob", rule_groups=["sshd"])
    key, basis = correlation_key_and_basis(ev)
    assert basis == "user"
    assert "bob" in key


def test_correlation_key_priority_rule_group_last():
    ev = _event(src_ip="", user="", rule_groups=["sshd", "authentication_failed"])
    key, basis = correlation_key_and_basis(ev)
    assert basis == "rule_group"
    assert "sshd" in key


def test_unkeyable_event_has_no_correlation_key():
    ev = _event(src_ip="", user="", rule_groups=[])
    assert correlation_key_and_basis(ev) is None


def test_ssh_brute_force_within_session_gap_is_one_incident(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-brute"
    now = datetime.datetime.now(datetime.timezone.utc)

    results = []
    for i in range(10):
        ev = _event(tenant=tenant, agent_id=agent, src_ip="9.9.9.9", time=now + datetime.timedelta(seconds=i * 5))
        results.append(process_event(db, ev, session_gap_seconds=600, max_span_seconds=14400))

    assert results[0].status == "created"
    assert all(r.status == "joined" for r in results[1:])
    incident_ids = {r.incident_id for r in results}
    assert len(incident_ids) == 1

    row = db.execute(select(incidents).where(incidents.c.id == incident_ids.pop())).mappings().one()
    assert row["alert_count"] == 10
    assert row["correlation_basis"] == "source_ip"
    assert row["state"] == "open"


def test_two_different_source_ips_make_two_incidents(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-multi-ip"
    now = datetime.datetime.now(datetime.timezone.utc)

    r1 = process_event(db, _event(tenant=tenant, agent_id=agent, src_ip="1.1.1.1", time=now))
    r2 = process_event(db, _event(tenant=tenant, agent_id=agent, src_ip="2.2.2.2", time=now))

    assert r1.status == "created"
    assert r2.status == "created"
    assert r1.incident_id != r2.incident_id


def test_alert_outside_session_gap_starts_a_new_incident(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-gap"
    now = datetime.datetime.now(datetime.timezone.utc)

    r1 = process_event(db, _event(tenant=tenant, agent_id=agent, src_ip="3.3.3.3", time=now), session_gap_seconds=60)
    r2 = process_event(
        db, _event(tenant=tenant, agent_id=agent, src_ip="3.3.3.3", time=now + datetime.timedelta(seconds=120)),
        session_gap_seconds=60,
    )

    assert r1.status == "created"
    assert r2.status == "created"
    assert r1.incident_id != r2.incident_id


def test_replay_is_idempotent_no_duplicate_membership_or_count_change(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-replay"
    now = datetime.datetime.now(datetime.timezone.utc)
    ev = _event(tenant=tenant, agent_id=agent, src_ip="4.4.4.4", alert_id="fixed-alert-id", time=now)

    r1 = process_event(db, ev)
    r2 = process_event(db, ev)  # exact same alert, replayed

    assert r1.status == "created"
    assert r2.status == "duplicate"
    assert r1.incident_id == r2.incident_id

    row = db.execute(select(incidents).where(incidents.c.id == r1.incident_id)).mappings().one()
    assert row["alert_count"] == 1  # not 2

    membership_count = db.execute(
        select(incident_alerts).where(incident_alerts.c.incident_id == r1.incident_id)
    ).mappings().all()
    assert len(membership_count) == 1


def test_out_of_order_alert_still_joins_and_extends_first_seen(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-ooo"
    now = datetime.datetime.now(datetime.timezone.utc)

    r1 = process_event(db, _event(tenant=tenant, agent_id=agent, src_ip="5.5.5.5", time=now))
    # Arrives second, but its own timestamp is BEFORE the first alert's -
    # a classic out-of-order delivery (e.g. two different queue
    # partitions, or a retry).
    r2 = process_event(
        db, _event(tenant=tenant, agent_id=agent, src_ip="5.5.5.5", time=now - datetime.timedelta(seconds=30)),
    )

    assert r1.status == "created"
    assert r2.status == "joined"
    assert r1.incident_id == r2.incident_id

    row = db.execute(select(incidents).where(incidents.c.id == r1.incident_id)).mappings().one()
    assert row["first_seen"] == now - datetime.timedelta(seconds=30)
    assert row["alert_count"] == 2


def test_max_span_caps_a_long_running_low_rate_attack_into_a_new_incident(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-longrun"
    now = datetime.datetime.now(datetime.timezone.utc)

    # Each alert is within session_gap of the previous one, but the whole
    # chain, if joined, would exceed max_span.
    r1 = process_event(
        db, _event(tenant=tenant, agent_id=agent, src_ip="6.6.6.6", time=now),
        session_gap_seconds=600, max_span_seconds=1000,
    )
    r2 = process_event(
        db, _event(tenant=tenant, agent_id=agent, src_ip="6.6.6.6", time=now + datetime.timedelta(seconds=1200)),
        session_gap_seconds=600, max_span_seconds=1000,
    )

    assert r1.status == "created"
    assert r2.status == "created"
    assert r1.incident_id != r2.incident_id


def test_capped_distinct_values_on_a_single_incident(db):
    """One attacking source IP trying 50 different usernames - correlates
    by source_ip (constant, so one incident per the priority rule and the
    "two different source IPs -> two incidents" VERIFY case), while the
    varying `users` field accumulates as a side observation on that one
    incident, capped."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-scan2"
    now = datetime.datetime.now(datetime.timezone.utc)

    first = None
    for i in range(50):
        ev = _event(
            tenant=tenant, agent_id=agent, src_ip="7.7.7.7",
            user=f"user{i}", time=now + datetime.timedelta(seconds=i),
        )
        r = process_event(db, ev, session_gap_seconds=600, max_span_seconds=14400)
        if first is None:
            first = r.incident_id
        assert r.incident_id == first, "all 50 should correlate into the same incident (same source_ip basis)"

    row = db.execute(select(incidents).where(incidents.c.id == first)).mappings().one()
    assert row["alert_count"] == 50
    assert len(row["users"]) == 20  # capped
    assert row["user_total"] == 50  # every alert carried a (distinct) username


def test_rule_ids_rule_groups_and_mitre_ids_accumulate_without_duplicates(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    agent = "agent-accum"
    now = datetime.datetime.now(datetime.timezone.utc)

    r1 = process_event(db, _event(
        tenant=tenant, agent_id=agent, src_ip="8.8.4.4", rule_id="5710",
        rule_groups=["sshd", "authentication_failed"], mitre_ids=["T1110.001"], time=now,
    ))
    r2 = process_event(db, _event(
        tenant=tenant, agent_id=agent, src_ip="8.8.4.4", rule_id="5712",
        rule_groups=["sshd", "invalid_login"], mitre_ids=["T1110.001", "T1021.004"],
        time=now + datetime.timedelta(seconds=5),
    ))
    assert r1.incident_id == r2.incident_id

    row = db.execute(select(incidents).where(incidents.c.id == r1.incident_id)).mappings().one()
    assert sorted(row["rule_ids"]) == ["5710", "5712"]
    assert sorted(row["rule_groups"]) == ["authentication_failed", "invalid_login", "sshd"]
    # order of first appearance, not sorted, and no duplicate of T1110.001
    assert row["mitre_ids"] == ["T1110.001", "T1021.004"]


def test_a_permanently_malformed_timestamp_raises_unparseable_not_a_generic_error(db):
    """Regression test (Phase 5A VERIFY): a bad timestamp must be
    distinguishable from a transient failure (a DB hiccup) - the consumer
    skips and commits past the first, but retries the second forever.
    Before this, both looked like the same generic exception, and a bad
    timestamp wedged a partition's consumer in an infinite retry loop."""
    ev = _event(src_ip="1.2.3.4")
    ev.time = "2026-10-04T05:00:118.000+0000"  # seconds=118 - not valid ISO8601

    with pytest.raises(correlator.UnparseableEvent):
        process_event(db, ev)
