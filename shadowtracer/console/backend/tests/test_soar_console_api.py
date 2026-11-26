"""Phase 9 Part B: console-supporting SOAR API — playbooks list/promote, settings, allowlist."""
import uuid

from sqlalchemy import text

from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401


def _hdr(client, db, tenant, role="admin"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def test_playbooks_list_includes_shipped_defaults(client, db, tenant):
    r = client.get("/api/soar/playbooks", headers=_hdr(client, db, tenant, role="analyst"))
    assert r.status_code == 200
    keys = {p["playbook_key"] for p in r.json()["playbooks"]}
    assert "builtin-ssh-brute-force" in keys and "builtin-ti-malicious-ip" in keys
    pb = next(p for p in r.json()["playbooks"] if p["playbook_key"] == "builtin-ssh-brute-force")
    assert pb["mode"] == "shadow" and pb["can_promote_to_auto"] is False   # no verdicts yet


def test_promote_refused_below_threshold(client, db, tenant):
    r = client.post("/api/soar/playbooks/builtin-ssh-brute-force/mode", json={"mode": "auto"},
                    headers=_hdr(client, db, tenant, role="admin"))
    assert r.status_code == 409 and ("verdicted" in r.json()["detail"] or "precision" in r.json()["detail"])


def test_promote_to_approval_ok_and_analyst_forbidden(client, db, tenant):
    # analyst can't change mode
    r = client.post("/api/soar/playbooks/builtin-ssh-brute-force/mode", json={"mode": "approval"},
                    headers=_hdr(client, db, tenant, role="analyst"))
    assert r.status_code == 403
    # admin can switch to approval (no gate)
    r = client.post("/api/soar/playbooks/builtin-ssh-brute-force/mode", json={"mode": "approval"},
                    headers=_hdr(client, db, tenant, role="admin"))
    assert r.status_code == 200 and r.json()["mode"] == "approval"


def test_settings_get_and_update(client, db, tenant):
    tid, tk = tenant
    r = client.get("/api/soar/settings", headers=_hdr(client, db, tenant, role="analyst"))
    assert r.status_code == 200 and "allowlist" in r.json() and "global_kill_switch" in r.json()
    r = client.put("/api/soar/settings", json={"rate_limit_per_hour": 25},
                   headers=_hdr(client, db, tenant, role="admin"))
    assert r.status_code == 200
    assert db.execute(text("SELECT rate_limit_per_hour FROM soar_tenant_settings WHERE tenant_key=:t"),
                      {"t": tk}).scalar() == 25
    assert db.execute(text("SELECT count(*) FROM audit_log WHERE action='soar.settings_updated'")).scalar() == 1


def test_settings_update_admin_only(client, db, tenant):
    r = client.put("/api/soar/settings", json={"rate_limit_per_hour": 25},
                   headers=_hdr(client, db, tenant, role="analyst"))
    assert r.status_code == 403


def test_allowlist_add_and_delete(client, db, tenant):
    tid, tk = tenant
    r = client.post("/api/soar/allowlist", json={"cidr": "203.0.113.0/24", "note": "lab doc range"},
                    headers=_hdr(client, db, tenant, role="admin"))
    assert r.status_code == 200
    eid = db.execute(text("SELECT id FROM soar_allowlist WHERE tenant_key=:t AND cidr='203.0.113.0/24'"),
                     {"t": tk}).scalar()
    assert eid
    r = client.delete(f"/api/soar/allowlist/{eid}", headers=_hdr(client, db, tenant, role="admin"))
    assert r.status_code == 200
    assert db.execute(text("SELECT count(*) FROM soar_allowlist WHERE id=:i"), {"i": eid}).scalar() == 0
