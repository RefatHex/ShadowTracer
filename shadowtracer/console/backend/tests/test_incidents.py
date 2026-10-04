import datetime
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import incidents as incidents_logic
from app.models import fingerprint_verdicts, fingerprints, incidents, users


def _make_user(db, tenant_id, email=None):
    from app import security
    user_id = db.execute(
        users.insert().values(
            tenant_id=tenant_id, email=email or f"analyst-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=security.hash_password("correct horse battery staple"), role="analyst",
        ).returning(users.c.id)
    ).scalar_one()
    db.commit()
    return user_id


def _make_closed_incident(db, tenant_key, fingerprint_key=None):
    fingerprint_key = fingerprint_key or uuid.uuid4().hex
    now = datetime.datetime.now(datetime.timezone.utc)
    incident_id = db.execute(
        incidents.insert().values(
            tenant_key=tenant_key, correlation_key="agent-1|srcip:8.8.8.8", correlation_basis="source_ip",
            agent_id="agent-1", first_seen=now, last_seen=now, alert_count=20, max_level=5,
            state="closed", closed_at=now, fingerprint_key=fingerprint_key, ruleset_version="2026.1",
        ).returning(incidents.c.id)
    ).scalar_one()
    db.execute(
        pg_insert(fingerprints).values(tenant_key=tenant_key, fingerprint_key=fingerprint_key)
        .on_conflict_do_nothing(index_elements=["tenant_key", "fingerprint_key"])
    )
    db.commit()
    return incident_id, fingerprint_key


def test_apply_triage_acknowledge_updates_status_no_verdict_recorded(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    analyst = _make_user(db, tenant_id)
    incident_id, fingerprint_key = _make_closed_incident(db, tenant_key)

    result = incidents_logic.apply_triage(db, tenant_key, incident_id, "acknowledge", analyst)

    assert result["triage_status"] == "acknowledged"
    row = db.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().one()
    assert row["triage_status"] == "acknowledged"
    verdicts = db.execute(
        select(fingerprint_verdicts).where(fingerprint_verdicts.c.incident_id == incident_id)
    ).mappings().all()
    assert len(verdicts) == 1
    assert verdicts[0]["verdict"] == "acknowledged"


def test_viewer_cannot_triage_is_enforced_at_the_route_not_here():
    """Documented, not tested here - apply_triage takes no role at all,
    by design, so the ONLY enforcement point is the route's RequireRole
    dependency (see test_rbac_enumeration.py + test_incidents_api.py's
    viewer-403 test). A business-logic-level role check here would be a
    second, divergeable copy of that rule."""


def test_five_false_positives_from_one_analyst_does_not_propose_suppression(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    analyst = _make_user(db, tenant_id)
    fingerprint_key = uuid.uuid4().hex

    last_result = None
    for _ in range(5):
        incident_id, _ = _make_closed_incident(db, tenant_key, fingerprint_key=fingerprint_key)
        last_result = incidents_logic.apply_triage(db, tenant_key, incident_id, "false_positive", analyst)

    assert last_result["suppression_state_changed_to"] is None
    fp_row = db.execute(
        select(fingerprints).where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
    ).mappings().one()
    assert fp_row["suppression_state"] == "none"


def test_five_false_positives_from_two_analysts_proposes_suppression_not_active(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    analyst_a = _make_user(db, tenant_id)
    analyst_b = _make_user(db, tenant_id)
    fingerprint_key = uuid.uuid4().hex

    analysts = [analyst_a, analyst_a, analyst_a, analyst_a, analyst_b]  # 4 from A, 1 from B - 2 distinct
    last_result = None
    for analyst in analysts:
        incident_id, _ = _make_closed_incident(db, tenant_key, fingerprint_key=fingerprint_key)
        last_result = incidents_logic.apply_triage(db, tenant_key, incident_id, "false_positive", analyst)

    assert last_result["suppression_state_changed_to"] == "proposed"
    fp_row = db.execute(
        select(fingerprints).where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
    ).mappings().one()
    assert fp_row["suppression_state"] == "proposed"
    assert fp_row["suppression_expires_at"] is None  # not active yet


def test_admin_approves_suppression_proposed_to_active(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    _, fingerprint_key = _make_closed_incident(db, tenant_key)
    db.execute(
        fingerprints.update().where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
        .values(suppression_state="proposed")
    )
    db.commit()

    expires_at = incidents_logic.approve_suppression(db, tenant_key, fingerprint_key, expiry_days=90)

    fp_row = db.execute(
        select(fingerprints).where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
    ).mappings().one()
    assert fp_row["suppression_state"] == "active"
    assert fp_row["suppression_expires_at"] is not None
    assert expires_at == fp_row["suppression_expires_at"]


def test_cannot_approve_suppression_that_was_never_proposed(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    _, fingerprint_key = _make_closed_incident(db, tenant_key)  # suppression_state defaults to 'none'

    with pytest.raises(incidents_logic.InvalidSuppressionTransition):
        incidents_logic.approve_suppression(db, tenant_key, fingerprint_key)


def test_expired_active_suppression_reverts_to_proposed(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    _, fingerprint_key = _make_closed_incident(db, tenant_key)
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    db.execute(
        fingerprints.update().where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
        .values(suppression_state="active", suppression_expires_at=past)
    )
    db.commit()

    state, expired_now = incidents_logic.effective_suppression_state(db, tenant_key, fingerprint_key)

    assert state == "proposed"
    assert expired_now is True
    fp_row = db.execute(
        select(fingerprints).where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
    ).mappings().one()
    assert fp_row["suppression_state"] == "proposed"
    assert fp_row["suppression_expires_at"] is None


def test_unexpired_active_suppression_stays_active(db, tenant_id):
    tenant_key = f"t-{uuid.uuid4().hex[:8]}"
    _, fingerprint_key = _make_closed_incident(db, tenant_key)
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    db.execute(
        fingerprints.update().where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
        .values(suppression_state="active", suppression_expires_at=future)
    )
    db.commit()

    state, expired_now = incidents_logic.effective_suppression_state(db, tenant_key, fingerprint_key)
    assert state == "active"
    assert expired_now is False
