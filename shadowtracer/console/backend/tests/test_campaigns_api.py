"""Phase 7.6 follow-up: the campaigns list endpoint that lets the console open a campaign graph.
Tenant scoping from the token; only multi-incident campaigns; most-linked first."""
import datetime
import uuid

from sqlalchemy import text

from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401


def _hdr(client, db, tenant, role="viewer"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def _mk_campaign(db, tenant_key, actor_value, incident_count):
    now = datetime.datetime.now(datetime.timezone.utc)
    db.execute(text(
        "INSERT INTO campaigns (tenant_key, fingerprint_key, actor_type, actor_value, first_seen, last_seen, incident_count) "
        "VALUES (:t, :fp, 'source_ip', :a, :fs, :ls, :n)"),
        {"t": tenant_key, "fp": uuid.uuid4().hex, "a": actor_value, "fs": now, "ls": now, "n": incident_count})
    db.commit()


def test_campaigns_listed_multi_incident_most_linked_first(client, db, tenant):
    _tid, tkey = tenant
    m = uuid.uuid4().hex[:8]
    _mk_campaign(db, tkey, f"10.0.0.{m[:2]}", 5)
    _mk_campaign(db, tkey, f"10.0.1.{m[:2]}", 12)
    _mk_campaign(db, tkey, f"10.0.2.{m[:2]}", 1)   # single-incident -> excluded

    rows = client.get("/api/campaigns", headers=_hdr(client, db, tenant)).json()
    mine = [c for c in rows if c["actor_value"].endswith(m[:2])]
    assert [c["incident_count"] for c in mine] == [12, 5]      # most-linked first, single-incident dropped
    assert all(c["actor_type"] == "source_ip" for c in mine)


def test_campaigns_tenant_isolation(client, db, tenant):
    _tid, tkey = tenant
    m = uuid.uuid4().hex[:8]
    _mk_campaign(db, tkey, f"10.9.9.{m[:2]}", 7)
    other_id = db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :k) RETURNING id"),
                          {"n": f"other-{m}", "k": f"key-other-{m}"}).scalar_one()
    db.commit()
    hdr = {"Authorization": f"Bearer {_token_for(client, db, other_id, f'o-{m}@x.io')}"}
    rows = client.get("/api/campaigns", headers=hdr).json()
    assert not any(c["actor_value"].endswith(m[:2]) for c in rows)
