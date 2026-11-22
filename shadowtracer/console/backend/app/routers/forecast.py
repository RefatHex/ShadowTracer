"""Phase 7.8: attack recurrence forecast endpoints (analyst+, tenant-scoped, read-only, experimental).

GET /api/fingerprints/{key}/forecast   next-likely window for a fingerprint
GET /api/campaigns/{id}/forecast        next-likely window for a campaign

A forecast is a HINT, never an alert - no blocking/suppression is driven by it. Recompute-on-view keeps
it current between the enricher's hourly recompute. Cross-tenant subject -> 404.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import forecast as forecast_logic
from ..deps import get_db
from ..rbac import ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api", tags=["forecast"])


@router.get("/fingerprints/{fingerprint_key}/forecast")
def fingerprint_forecast(fingerprint_key: str, db: Session = Depends(get_db),
                         current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    exists = db.execute(text("SELECT 1 FROM fingerprints WHERE tenant_key=:t AND fingerprint_key=:k"),
                        {"t": current_user.tenant_key, "k": fingerprint_key}).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="fingerprint not found")
    return forecast_logic.get_forecast(db, current_user.tenant_key, "fingerprint", fingerprint_key)


@router.get("/campaigns/{campaign_id}/forecast")
def campaign_forecast(campaign_id: int, db: Session = Depends(get_db),
                      current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    exists = db.execute(text("SELECT 1 FROM campaigns WHERE tenant_key=:t AND id=:k"),
                        {"t": current_user.tenant_key, "k": campaign_id}).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="campaign not found")
    return forecast_logic.get_forecast(db, current_user.tenant_key, "campaign", str(campaign_id))
