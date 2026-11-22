"""Phase 9 (c): approval/block expiry sweep and versioned playbooks."""
import datetime

from sqlalchemy import text

from app.soar import playbooks, worker
from conftest import insert_tenant

TK = "soar-exp-tenant"
NOW = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _incident(db, tk):
    return db.execute(text("""
        INSERT INTO incidents (tenant_key, correlation_key, correlation_basis, agent_id,
            first_seen, last_seen, state, source_ips)
        VALUES (:t, 'ck', 'source_ip', '001', :n, :n, 'open', '{8.8.8.8}') RETURNING id"""),
        {"t": tk, "n": NOW}).scalar()


def test_unanswered_request_expires_as_no_action(db):
    insert_tenant(db, TK)
    worker._TENANT_ID.clear()
    iid = _incident(db, TK)
    db.execute(text("""INSERT INTO soar_actions (tenant_key, incident_id, playbook_key, action_type,
        target, agent_id, mode, status, created_at)
        VALUES (:t, :i, 'builtin-ssh-brute-force', 'block_ip', '8.8.8.8', '001', 'approval',
        'requested', :old)"""), {"t": TK, "i": iid, "old": NOW - datetime.timedelta(hours=2)})
    db.commit()
    reversed_calls = []
    worker.expire_stale(db, NOW, reverse_fn=lambda *a: reversed_calls.append(a),
                        base_url_fn=lambda t: "http://mgr")
    st = db.execute(text("SELECT status FROM soar_actions WHERE incident_id=:i"), {"i": iid}).scalar()
    assert st == "expired" and reversed_calls == []                    # no-action: nothing dispatched
    assert db.execute(text("SELECT count(*) FROM audit_log WHERE action='soar.approval_expired'")
                      ).scalar() == 1


def test_executed_block_past_expiry_is_reversed(db):
    insert_tenant(db, TK)
    worker._TENANT_ID.clear()
    iid = _incident(db, TK)
    db.execute(text("""INSERT INTO soar_actions (tenant_key, incident_id, playbook_key, action_type,
        target, agent_id, mode, status, block_expires_at)
        VALUES (:t, :i, 'builtin-ssh-brute-force', 'block_ip', '8.8.8.8', '001', 'approval',
        'executed', :exp)"""), {"t": TK, "i": iid, "exp": NOW - datetime.timedelta(minutes=1)})
    db.commit()
    calls = []
    worker.expire_stale(db, NOW, reverse_fn=lambda base, agent, ip: calls.append((agent, ip)),
                        base_url_fn=lambda t: "http://mgr")
    st = db.execute(text("SELECT status, expired_at FROM soar_actions WHERE incident_id=:i"),
                    {"i": iid}).mappings().first()
    assert st["status"] == "expired" and st["expired_at"] and calls == [("001", "8.8.8.8")]
    assert db.execute(text("SELECT count(*) FROM audit_log WHERE action='soar.block_expired'")
                      ).scalar() == 1


def test_upsert_playbook_versions_and_audits(db):
    insert_tenant(db, TK)
    tid = db.execute(text("SELECT id FROM tenants WHERE tenant_key=:t"), {"t": TK}).scalar()
    d1 = {"steps": [{"action": "block_ip", "mode": "approval"}]}
    pb = playbooks.upsert_playbook(db, TK, tid, "builtin-ssh-brute-force", d1, "admin", block_seconds=1800)
    assert pb["version"] == 1 and pb["block_seconds"] == 1800
    d2 = {"steps": [{"action": "block_ip", "mode": "auto"}]}
    pb = playbooks.upsert_playbook(db, TK, tid, "builtin-ssh-brute-force", d2, "admin")
    assert pb["version"] == 2
    hist = db.execute(text("SELECT count(*) FROM soar_playbook_versions WHERE playbook_key=:p"),
                      {"p": "builtin-ssh-brute-force"}).scalar()
    assert hist == 2                                                   # both versions kept
    assert db.execute(text("SELECT count(*) FROM audit_log WHERE action='soar.playbook_edited'")
                      ).scalar() == 2


def test_block_seconds_for_prefers_override_then_default(db):
    insert_tenant(db, TK)
    # no stored row -> shipped default definition (ti playbook = 7200)
    assert playbooks.block_seconds_for(db, TK, "builtin-ti-malicious-ip", 3600) == 7200
    # unknown playbook -> tenant default
    assert playbooks.block_seconds_for(db, TK, "nope", 3600) == 3600
