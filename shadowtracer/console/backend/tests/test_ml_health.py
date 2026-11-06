"""Phase 7.0: /health/detail "ml" - score distribution per served model."""
from sqlalchemy import text

from app import health as health_checks
from test_incidents_api import _make_incident, app_settings, client, tenant  # noqa: F401


def test_ml_score_distribution_per_model(db, tenant):
    _, tenant_key = tenant
    model = "incident-risk-test:1"
    for score in (0.05, 0.55, 0.57, 1.0):
        i = _make_incident(db, tenant_key, state="closed")
        db.execute(text("UPDATE incidents SET closed_at = now(), ml_score = :s, ml_model = :m, ml_scored_at = now(), "
                        "ml_reasons = '{}'::jsonb WHERE id = :i"), {"s": score, "m": model, "i": i})
    db.commit()
    m = health_checks.ml_scores(db)["models"][model]
    assert m["scored"] == 4 and m["deciles"][0] == 1 and m["deciles"][5] == 2 and m["deciles"][9] == 1
