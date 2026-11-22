"""Phase 9 (b): earned autonomy — shadow precision per playbook and the promotion gate (shadow->auto
only above threshold over enough verdicted incidents), audited."""
import datetime

import pytest
from sqlalchemy import text

from app.soar import earned_autonomy as ea
from conftest import insert_tenant

TK = "soar-ea-tenant"
PB = "builtin-ssh-brute-force"
NOW = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)


@pytest.fixture
def tid(db):
    insert_tenant(db, TK)
    return db.execute(text("SELECT id FROM tenants WHERE tenant_key=:t"), {"t": TK}).scalar()


def _shadow_action_on_verdicted_incident(db, verdict: str, ip: str):
    """A shadow action whose incident later got analyst verdict `verdict` (triage_status)."""
    iid = db.execute(text("""
        INSERT INTO incidents (tenant_key, correlation_key, correlation_basis, agent_id,
            first_seen, last_seen, state, triage_status, source_ips)
        VALUES (:t, :ck, 'source_ip', '001', :now, :now, 'closed', :v, :ips) RETURNING id"""),
        {"t": TK, "ck": f"ck-{ip}", "now": NOW, "v": verdict, "ips": [ip]}).scalar()
    db.execute(text("""INSERT INTO soar_actions (tenant_key, incident_id, playbook_key, action_type,
        target, mode, status) VALUES (:t, :i, :p, 'block_ip', :ip, 'shadow', 'shadow')"""),
        {"t": TK, "i": iid, "p": PB, "ip": ip})
    db.commit()


def test_default_mode_is_shadow_and_persists(db, tid):
    assert ea.playbook_mode(db, TK, PB) == "shadow"
    row = db.execute(text("SELECT mode FROM soar_playbooks WHERE tenant_key=:t AND playbook_key=:p"),
                     {"t": TK, "p": PB}).scalar()
    assert row == "shadow"


def test_compute_precision_counts_distinct_verdicted_incidents(db, tid):
    for i in range(9):
        _shadow_action_on_verdicted_incident(db, "escalated", f"8.8.8.{i}")       # 9 true positives
    _shadow_action_on_verdicted_incident(db, "false_positive", "9.9.9.9")         # 1 false positive
    _shadow_action_on_verdicted_incident(db, "new", "1.1.1.1")                    # no verdict -> excluded
    stats = ea.compute_precision(db, TK, PB)
    assert stats == {"tp": 9, "fp": 1, "count": 10, "precision": 0.9}


def test_promotion_refused_below_precision(db, tid):
    for i in range(18):
        _shadow_action_on_verdicted_incident(db, "escalated", f"8.8.{i}.1")
    for i in range(2):
        _shadow_action_on_verdicted_incident(db, "false_positive", f"9.9.{i}.1")  # 18/20 = 0.90 < 0.95
    res = ea.set_mode(db, TK, tid, PB, "auto", "admin@x.io")
    assert res["ok"] is False and "precision" in res["reason"]
    assert ea.playbook_mode(db, TK, PB) == "shadow"                               # unchanged
    assert db.execute(text("SELECT count(*) FROM audit_log WHERE action='soar.promotion_refused'")
                      ).scalar() == 1


def test_promotion_refused_below_count(db, tid):
    for i in range(5):
        _shadow_action_on_verdicted_incident(db, "escalated", f"8.8.{i}.2")       # 100% but only 5 < 20
    res = ea.set_mode(db, TK, tid, PB, "auto", "admin@x.io")
    assert res["ok"] is False and "verdicted incidents" in res["reason"]


def test_promotion_allowed_above_threshold_is_audited(db, tid):
    for i in range(20):
        _shadow_action_on_verdicted_incident(db, "escalated", f"8.8.{i}.3")       # 20/20 = 1.00 >= 0.95
    res = ea.set_mode(db, TK, tid, PB, "auto", "admin@x.io")
    assert res["ok"] is True and res["mode"] == "auto"
    assert ea.playbook_mode(db, TK, PB) == "auto"
    aud = db.execute(text("SELECT target, outcome FROM audit_log WHERE action='soar.playbook_mode_changed'")
                     ).mappings().first()
    assert aud["outcome"] == "auto" and "shadow->auto" in aud["target"]


def test_demote_to_shadow_is_unconditional(db, tid):
    ea.set_mode(db, TK, tid, PB, "approval", "admin@x.io")                        # non-auto needs no gate
    assert ea.playbook_mode(db, TK, PB) == "approval"
