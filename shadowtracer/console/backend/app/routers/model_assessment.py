"""Phase 7.4: the XGBoost historical classifier's assessment of one incident (analyst+). Class +
probability + plain-language SHAP reasons, written by the ml-enricher at incident close into
incidents.ml_reasons. ADVISORY ONLY - a hint shown to analysts, never used to filter, suppress or
auto-close an incident (docs/ML_FOUNDATION.md). Tenant comes from the token; the lookup is
tenant-scoped, so a cross-tenant id returns 404 and never leaks another tenant's incident."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..deps import get_db
from ..rbac import ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api", tags=["model-assessment"])

MODEL_PREFIX = "incident-classifier"   # must match shadowtracer_ml.classifier.MODEL_NAME


class ModelAssessment(BaseModel):
    incident_id: int
    model_version: str                 # "incident-classifier:<version>"
    predicted_class: str               # "attack" | "benign"
    probability: float                 # P(attack), 0..1
    reasons: list[str]                 # plain-language SHAP reasons, top contributors first
    scored_at: str | None
    advisory: bool = True              # always: the model never triggers an action
    experimental: bool = False         # 7.4 item 5: from the served model version's `experimental` tag


@router.get("/incidents/{incident_id}/model-assessment", response_model=ModelAssessment | None)
def model_assessment(incident_id: int, db: Session = Depends(get_db),
                     current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    row = db.execute(text(
        "SELECT ml_reasons, ml_scored_at FROM incidents WHERE id = :i AND tenant_key = :t"),
        {"i": incident_id, "t": current_user.tenant_key}).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")   # cross-tenant -> 404
    payload = row["ml_reasons"] or {}
    models = payload.get("models", {}) if isinstance(payload, dict) else {}
    entry = next(((k, v) for k, v in models.items() if k.split(":", 1)[0] == MODEL_PREFIX and "class" in v), None)
    if entry is None:
        return None   # not scored by the classifier yet (not served, or closed before it was promoted)
    key, v = entry
    return ModelAssessment(
        incident_id=incident_id, model_version=key, predicted_class=v["class"],
        probability=float(v.get("prob", v.get("score", 0.0))), reasons=list(v.get("reasons") or []),
        experimental=bool(v.get("experimental", False)),
        scored_at=row["ml_scored_at"].isoformat() if row["ml_scored_at"] else None)
