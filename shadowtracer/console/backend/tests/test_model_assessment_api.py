"""Phase 7.4: the model-assessment API. Reads the classifier entry the ml-enricher wrote into
incidents.ml_reasons; covers the happy path, the not-yet-scored case, cross-tenant 404, and that it
is analyst+ only."""
import json
import uuid

from sqlalchemy import text

from test_incidents_api import _make_incident, _token_for, app_settings, client, tenant  # noqa: F401


def _hdr(client, db, tenant, role="analyst"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def _other_tenant_incident(db):
    key = f"other-{uuid.uuid4().hex[:8]}"
    db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :k)"), {"n": key, "k": key})
    db.commit()
    return _make_incident(db, key, agent_id="x")


def _set_assessment(db, incident_id, cls="attack", prob=0.87, reasons=("raised by: the highest alert severity",),
                    experimental=True):
    payload = {"feature_version": "f1", "models": {
        "incident-classifier:3": {"score": prob, "prob": prob, "class": cls, "reasons": list(reasons),
                                  "experimental": experimental}}}
    db.execute(text("UPDATE incidents SET ml_reasons = CAST(:r AS jsonb), ml_scored_at = now() WHERE id = :i"),
               {"r": json.dumps(payload), "i": incident_id})
    db.commit()


def test_model_assessment_happy_path(client, db, tenant):
    _tid, tkey = tenant
    inc = _make_incident(db, tkey, agent_id="060")
    _set_assessment(db, inc, cls="attack", prob=0.91)
    r = client.get(f"/api/incidents/{inc}/model-assessment", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    body = r.json()
    assert body["predicted_class"] == "attack" and body["probability"] == 0.91
    assert body["model_version"] == "incident-classifier:3" and body["advisory"] is True
    assert body["experimental"] is True   # 7.4 item 5: surfaced from the stored entry for the panel badge
    assert body["reasons"] and body["reasons"][0].startswith("raised by:")


def test_model_assessment_not_scored_returns_null(client, db, tenant):
    inc = _make_incident(db, tenant[1], agent_id="060")   # no classifier entry
    r = client.get(f"/api/incidents/{inc}/model-assessment", headers=_hdr(client, db, tenant))
    assert r.status_code == 200 and r.json() is None


def test_model_assessment_cross_tenant_is_404(client, db, tenant):
    other = _other_tenant_incident(db)
    r = client.get(f"/api/incidents/{other}/model-assessment", headers=_hdr(client, db, tenant))
    assert r.status_code == 404


def test_model_assessment_viewer_forbidden(client, db, tenant):
    inc = _make_incident(db, tenant[1], agent_id="060")
    _set_assessment(db, inc)
    r = client.get(f"/api/incidents/{inc}/model-assessment", headers=_hdr(client, db, tenant, role="viewer"))
    assert r.status_code == 403
