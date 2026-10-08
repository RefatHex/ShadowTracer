"""Phase 5B Step 5: campaign linking. Real PostgreSQL only (campaigns,
campaign_incidents) - drives the real close_eligible_incidents (not
link_campaign directly), so this exercises the exact same code path the
real closer runs. Real ClickHouse is still touched (fingerprint
computation writes fingerprint_occurrences as part of closing), via the
same ch_client fixture every other closer test uses.
"""

import datetime
import uuid

from sqlalchemy import select

from conftest import TEST_CLICKHOUSE_DB as CH_DB
from shadowtracer_correlate.closer import close_eligible_incidents
from shadowtracer_correlate.models import campaign_incidents, campaigns, incidents

INTERNAL_RANGES = ["10.0.0.0/8"]


def _insert_incident(db, tenant, agent, first_seen, last_seen, source_ips=None, users=None, alert_count=10):
    result = db.execute(
        incidents.insert().values(
            tenant_key=tenant, correlation_key=f"{agent}|srcip:{(source_ips or ['8.8.8.8'])[0]}",
            correlation_basis="source_ip" if source_ips else "user",
            agent_id=agent, first_seen=first_seen, last_seen=last_seen,
            alert_count=alert_count, max_level=5,
            rule_ids=["5710"], rule_groups=["sshd", "authentication_failed"], mitre_ids=["T1110.001"],
            source_ips=source_ips or [], source_ip_total=len(source_ips or []),
            users=users or [], user_total=len(users or []),
        ).returning(incidents.c.id)
    )
    db.commit()
    return result.scalar_one()


def _close_one(db, ch_client):
    closed = close_eligible_incidents(db, ch_client, CH_DB, session_gap_seconds=600, internal_ranges=INTERNAL_RANGES)
    assert len(closed) == 1, f"expected exactly one incident eligible to close, got {closed}"
    return closed[0]


def _campaign_for_incident(db, incident_id):
    row = db.execute(
        select(campaigns).join(campaign_incidents, campaigns.c.id == campaign_incidents.c.campaign_id)
        .where(campaign_incidents.c.incident_id == incident_id)
    ).mappings().first()
    return row


def test_two_incidents_same_actor_same_fingerprint_within_24h_one_campaign_two_incidents(db, ch_client):
    """Brute force from one IP, repeated twice inside 24h -> ONE campaign,
    2 incidents."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.10"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    id1 = _insert_incident(
        db, tenant, agent, first_seen=base, last_seen=base + datetime.timedelta(minutes=2), source_ips=[ip],
    )
    closed1 = _close_one(db, ch_client)
    assert closed1 == id1
    campaign1 = _campaign_for_incident(db, id1)
    assert campaign1 is not None
    assert campaign1["incident_count"] == 1

    second_start = base + datetime.timedelta(hours=23)  # within 24h of incident 1's last_seen
    id2 = _insert_incident(
        db, tenant, agent, first_seen=second_start, last_seen=second_start + datetime.timedelta(minutes=2),
        source_ips=[ip],
    )
    closed2 = _close_one(db, ch_client)
    assert closed2 == id2
    campaign2 = _campaign_for_incident(db, id2)

    assert campaign2["id"] == campaign1["id"], "same actor, same fingerprint, within 24h - must be the SAME campaign"
    assert campaign2["incident_count"] == 2


def test_same_fingerprint_different_actor_is_a_separate_campaign(db, ch_client):
    """Same attack from a second IP -> same fingerprint but a separate
    campaign. Fingerprinting only cares about internal-vs-external
    classification for the source IP (never the literal address, per
    Phase 5A Step 3), so two different EXTERNAL IPs genuinely produce the
    same fingerprint_key here - this test is real proof campaign actor
    identity (the literal IP) is a materially different concept from the
    fingerprint's actor_class bucket."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    id1 = _insert_incident(
        db, tenant, agent, first_seen=base, last_seen=base + datetime.timedelta(minutes=2),
        source_ips=["203.0.113.11"],
    )
    closed1 = _close_one(db, ch_client)
    campaign1 = _campaign_for_incident(db, id1)

    id2 = _insert_incident(
        db, tenant, agent, first_seen=base + datetime.timedelta(hours=1),
        last_seen=base + datetime.timedelta(hours=1, minutes=2),
        source_ips=["203.0.113.22"],  # different IP, same tenant/agent/shape
    )
    closed2 = _close_one(db, ch_client)
    campaign2 = _campaign_for_incident(db, id2)

    incident1 = db.execute(select(incidents).where(incidents.c.id == id1)).mappings().one()
    incident2 = db.execute(select(incidents).where(incidents.c.id == id2)).mappings().one()
    assert incident1["fingerprint_key"] == incident2["fingerprint_key"], "sanity check: same fingerprint expected"

    assert campaign1["id"] != campaign2["id"], "different actor - must NOT be the same campaign"
    assert campaign1["actor_value"] == "203.0.113.11"
    assert campaign2["actor_value"] == "203.0.113.22"


def test_same_actor_same_fingerprint_25h_apart_not_linked(db, ch_client):
    """Same actor, same fingerprint, 25h apart -> NOT linked. Tests the
    window edge explicitly: 23h (above) links, 25h does not."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.33"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    id1 = _insert_incident(
        db, tenant, agent, first_seen=base, last_seen=base + datetime.timedelta(minutes=2), source_ips=[ip],
    )
    closed1 = _close_one(db, ch_client)
    campaign1 = _campaign_for_incident(db, id1)
    assert campaign1["incident_count"] == 1

    second_start = base + datetime.timedelta(hours=25)  # past the 24h window
    id2 = _insert_incident(
        db, tenant, agent, first_seen=second_start, last_seen=second_start + datetime.timedelta(minutes=2),
        source_ips=[ip],
    )
    closed2 = _close_one(db, ch_client)
    campaign2 = _campaign_for_incident(db, id2)

    assert campaign2["id"] != campaign1["id"], "25h apart - must NOT be linked into the same campaign"
    assert campaign2["incident_count"] == 1
    # The original campaign must be untouched by the later, unlinked incident.
    campaign1_after = db.execute(select(campaigns).where(campaigns.c.id == campaign1["id"])).mappings().one()
    assert campaign1_after["incident_count"] == 1


def test_incident_with_no_source_ip_falls_back_to_user(db, ch_client):
    """Actor definition: source IP first, then user."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    id1 = _insert_incident(
        db, tenant, agent, first_seen=base, last_seen=base + datetime.timedelta(minutes=2),
        source_ips=[], users=["alice"],
    )
    _close_one(db, ch_client)
    campaign1 = _campaign_for_incident(db, id1)
    assert campaign1["actor_type"] == "user"
    assert campaign1["actor_value"] == "alice"


def test_incident_with_neither_source_ip_nor_user_gets_no_campaign(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    id1 = _insert_incident(
        db, tenant, agent, first_seen=base, last_seen=base + datetime.timedelta(minutes=2),
        source_ips=[], users=[],
    )
    _close_one(db, ch_client)
    assert _campaign_for_incident(db, id1) is None


def test_campaign_membership_is_idempotent_on_replay(db, ch_client):
    """Idempotent on replay: re-running link_campaign for the same
    (campaign, incident) pair must not create a second membership row -
    simulates what a retried close would do (campaign_incidents'
    unique constraint, defensively, on top of the structural guarantee
    an incident only closes once)."""
    from shadowtracer_correlate.campaigns import link_campaign

    tenant = f"t-{uuid.uuid4().hex[:8]}"
    agent = f"agent-{uuid.uuid4().hex[:8]}"
    ip = "203.0.113.44"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    id1 = _insert_incident(
        db, tenant, agent, first_seen=base, last_seen=base + datetime.timedelta(minutes=2), source_ips=[ip],
    )
    _close_one(db, ch_client)
    incident_row = db.execute(select(incidents).where(incidents.c.id == id1)).mappings().one()

    db.commit()  # the SELECT above auto-began a transaction - close it out before link_campaign's own writes
    link_campaign(
        db, tenant, incident_row["fingerprint_key"], id1,
        incident_row["source_ips"], incident_row["users"], incident_row["first_seen"], incident_row["last_seen"],
    )
    db.commit()

    memberships = db.execute(
        select(campaign_incidents).where(campaign_incidents.c.incident_id == id1)
    ).all()
    assert len(memberships) == 1, "re-linking the same incident must not create a duplicate membership row"
