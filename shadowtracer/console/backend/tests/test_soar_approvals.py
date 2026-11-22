"""Phase 9 (c): approvals API — approve -> execute, deny, undo, four-eyes, reason-required, RBAC,
cross-tenant isolation. Dispatch (Wazuh AR) is mocked; the manager endpoint is monkeypatched.
"""
import uuid

import pytest
from sqlalchemy import text

from app.soar import approvals
from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401


@pytest.fixture(autouse=True)
def _mock_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(approvals.actions, "apply_block",
                        lambda base, agent, ip: calls.append(("add", base, agent, ip)))
    monkeypatch.setattr(approvals.actions, "reverse_block",
                        lambda base, agent, ip: calls.append(("del", base, agent, ip)))
    return calls


def _endpoint(monkeypatch, tenant_key):
    monkeypatch.setattr(approvals.wazuh_api, "endpoints", lambda: {tenant_key: "http://mgr:55000"})


def _requested_action(db, tenant_key, *, action_type="block_ip", target="8.8.8.8", agent_id="001"):
    iid = db.execute(text("""
        INSERT INTO incidents (tenant_key, correlation_key, correlation_basis, agent_id,
            first_seen, last_seen, state, source_ips)
        VALUES (:t, :ck, 'source_ip', :ag, now(), now(), 'open', :ips) RETURNING id"""),
        {"t": tenant_key, "ck": f"ck-{uuid.uuid4().hex[:6]}", "ag": agent_id, "ips": [target]}).scalar()
    aid = db.execute(text("""
        INSERT INTO soar_actions (tenant_key, incident_id, playbook_key, action_type, target,
            agent_id, mode, status, block_seconds)
        VALUES (:t, :i, 'builtin-ssh-brute-force', :at, :tg, :ag, 'approval', 'requested', 120)
        RETURNING id"""),
        {"t": tenant_key, "i": iid, "at": action_type, "tg": target, "ag": agent_id}).scalar()
    db.commit()
    return aid


def _hdr(client, db, tenant, role="analyst"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def test_approve_executes_block_and_audits(client, db, tenant, monkeypatch, _mock_dispatch):
    tid, tk = tenant
    _endpoint(monkeypatch, tk)
    aid = _requested_action(db, tk)
    r = client.post(f"/api/soar/approvals/{aid}/approve", json={"reason": "confirmed malicious"},
                    headers=_hdr(client, db, tenant))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "executed" and r.json()["block_expires_at"]
    assert _mock_dispatch[0][0] == "add" and _mock_dispatch[0][3] == "8.8.8.8"
    aud = db.execute(text("SELECT count(*) FROM audit_log WHERE action='soar.executed'")).scalar()
    assert aud == 1


def test_approve_then_undo_reverses(client, db, tenant, monkeypatch, _mock_dispatch):
    tid, tk = tenant
    _endpoint(monkeypatch, tk)
    aid = _requested_action(db, tk)
    h = _hdr(client, db, tenant)
    client.post(f"/api/soar/approvals/{aid}/approve", json={"reason": "x"}, headers=h)
    r = client.post(f"/api/soar/actions/{aid}/undo", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "undone"
    assert any(c[0] == "del" for c in _mock_dispatch)


def test_approve_requires_reason(client, db, tenant, monkeypatch):
    tid, tk = tenant
    _endpoint(monkeypatch, tk)
    aid = _requested_action(db, tk)
    r = client.post(f"/api/soar/approvals/{aid}/approve", json={"reason": "  "},
                    headers=_hdr(client, db, tenant))
    assert r.status_code == 400


def test_four_eyes_owner_cannot_approve(client, db, tenant, monkeypatch):
    tid, tk = tenant
    _endpoint(monkeypatch, tk)
    aid = _requested_action(db, tk)
    # make the approver the playbook owner
    email = f"owner-{uuid.uuid4().hex[:8]}@x.io"
    token = _token_for(client, db, tid, email, role="analyst")
    uid = db.execute(text("SELECT id FROM users WHERE email=:e"), {"e": email}).scalar()
    db.execute(text("INSERT INTO soar_playbooks (tenant_key, playbook_key, mode, updated_by) "
                    "VALUES (:t, 'builtin-ssh-brute-force', 'approval', :u)"), {"t": tk, "u": str(uid)})
    db.commit()
    r = client.post(f"/api/soar/approvals/{aid}/approve", json={"reason": "self"},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403 and "four-eyes" in r.json()["detail"]


def test_viewer_cannot_approve(client, db, tenant, monkeypatch):
    tid, tk = tenant
    _endpoint(monkeypatch, tk)
    aid = _requested_action(db, tk)
    r = client.post(f"/api/soar/approvals/{aid}/approve", json={"reason": "x"},
                    headers=_hdr(client, db, tenant, role="viewer"))
    assert r.status_code == 403


def test_deny_marks_refused(client, db, tenant, monkeypatch):
    tid, tk = tenant
    _endpoint(monkeypatch, tk)
    aid = _requested_action(db, tk)
    r = client.post(f"/api/soar/approvals/{aid}/deny", json={"reason": "false positive"},
                    headers=_hdr(client, db, tenant))
    assert r.status_code == 200 and r.json()["status"] == "refused"
    assert r.json()["refuse_reason"].startswith("denied:")


def test_cross_tenant_action_is_404(client, db, tenant, monkeypatch):
    tid, tk = tenant
    other = f"other-{uuid.uuid4().hex[:8]}"
    db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:k,:k)"), {"k": other})
    db.commit()
    aid = _requested_action(db, other)                           # action belongs to another tenant
    r = client.post(f"/api/soar/approvals/{aid}/approve", json={"reason": "x"},
                    headers=_hdr(client, db, tenant))
    assert r.status_code == 404


def test_pending_queue_lists_requested(client, db, tenant, monkeypatch):
    tid, tk = tenant
    _requested_action(db, tk)
    r = client.get("/api/soar/approvals", headers=_hdr(client, db, tenant))
    assert r.status_code == 200 and len(r.json()["pending"]) == 1
