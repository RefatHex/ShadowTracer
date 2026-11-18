"""Phase 7.5: the similar-incidents API. The Qdrant query is monkeypatched (no vector store needed);
this covers the happy path, cross-tenant 404, and that the tenant scoping + Postgres join never let
another tenant's incident come back even if Qdrant returned one."""
import uuid

from sqlalchemy import text

from app import qdrant_similar

from test_incidents_api import _make_incident, _token_for, app_settings, client, tenant  # noqa: F401


def _hdr(client, db, tenant, role="analyst"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def _other_tenant_incident(db):
    key = f"other-{uuid.uuid4().hex[:8]}"
    db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :k)"), {"n": key, "k": key})
    db.commit()
    return _make_incident(db, key, agent_id="x")


def test_similar_returns_tenant_incidents_with_score(client, db, tenant, monkeypatch):
    _tid, tkey = tenant
    base = _make_incident(db, tkey, agent_id="060")
    a = _make_incident(db, tkey, agent_id="060")
    b = _make_incident(db, tkey, agent_id="061")
    monkeypatch.setattr(qdrant_similar, "similar",
                        lambda t, i, k=5: [{"incident_id": a, "score": 0.92}, {"incident_id": b, "score": 0.81}])
    r = client.get(f"/api/incidents/{base}/similar", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    body = r.json()
    assert [s["incident_id"] for s in body] == [a, b]      # ordered by score
    assert body[0]["score"] == 0.92 and body[0]["agent_id"] == "060"


def test_similar_cross_tenant_id_is_404(client, db, tenant, monkeypatch):
    # an incident id that belongs to ANOTHER tenant must 404, never query vectors
    _tid, tkey = tenant
    other = _other_tenant_incident(db)
    called = {"q": False}
    monkeypatch.setattr(qdrant_similar, "similar", lambda *a, **k: called.__setitem__("q", True) or [])
    r = client.get(f"/api/incidents/{other}/similar", headers=_hdr(client, db, tenant))
    assert r.status_code == 404
    assert called["q"] is False                            # never even reached the vector store


def test_similar_never_returns_another_tenants_incident(client, db, tenant, monkeypatch):
    # defence in depth: even if Qdrant (wrongly) returned a foreign incident id, the tenant-scoped
    # Postgres join drops it - it never appears in the response.
    _tid, tkey = tenant
    base = _make_incident(db, tkey, agent_id="060")
    foreign = _other_tenant_incident(db)
    monkeypatch.setattr(qdrant_similar, "similar", lambda t, i, k=5: [{"incident_id": foreign, "score": 0.99}])
    r = client.get(f"/api/incidents/{base}/similar", headers=_hdr(client, db, tenant))
    assert r.status_code == 200 and r.json() == []         # foreign id filtered out by the tenant join


def test_similar_viewer_forbidden(client, db, tenant):
    base = _make_incident(db, tenant[1], agent_id="060")
    r = client.get(f"/api/incidents/{base}/similar", headers=_hdr(client, db, tenant, role="viewer"))
    assert r.status_code == 403                            # analyst+ only
