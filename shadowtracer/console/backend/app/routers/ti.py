"""Phase 6.3: threat-intel settings and on-demand VirusTotal lookups (THREAT_INTEL.md §3.4).

The backend never calls VirusTotal and never holds a key: a lookup is answered from the
tenant's verdict cache or queued for ti-sync's VirusTotal worker, which applies the same
cache, API limits and daily budget as the automatic FIM path. Hashes only (SHA-256).
"""
import datetime
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..deps import get_db
from ..rbac import ADMIN_ONLY, ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api/ti", tags=["threat-intel"])
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TiSettings(BaseModel):
    vt_enabled: bool = False
    vt_daily_budget: int = Field(default=500, ge=0, le=1_000_000)


class LookupRequest(BaseModel):
    sha256: str


class Verdict(BaseModel):
    sha256: str
    status: str                     # malicious | clean | unknown
    malicious: int
    suspicious: int
    total: int
    labels: list[str]
    first_submission: datetime.datetime | None
    last_analysis: datetime.datetime | None
    permalink: str
    fetched_at: datetime.datetime
    expires_at: datetime.datetime


def _settings(db: Session, tenant_key: str) -> TiSettings:
    r = db.execute(text("SELECT vt_enabled, vt_daily_budget FROM ti_tenant_settings WHERE tenant_key = :t"),
                   {"t": tenant_key}).mappings().first()
    return TiSettings(**r) if r else TiSettings()


def _verdict(db: Session, tenant_key: str, sha256: str):
    r = db.execute(text("SELECT * FROM vt_verdicts WHERE tenant_key = :t AND sha256 = :h AND expires_at > now()"),
                   {"t": tenant_key, "h": sha256}).mappings().first()
    return Verdict(**{k: r[k] for k in Verdict.model_fields}) if r else None


def _queue_state(db: Session, tenant_key: str, settings: TiSettings) -> str:
    used = db.execute(text("SELECT count(*) FROM vt_calls WHERE tenant_key = :t AND called_at >= date_trunc('day', now())"),
                      {"t": tenant_key}).scalar_one()
    return "budget_reached" if used >= settings.vt_daily_budget else "queued"


def _sha256(value: str) -> str:
    h = value.strip().lower()
    if not SHA256.match(h):
        raise HTTPException(status_code=422, detail="sha256 must be 64 hex characters")
    return h


@router.get("/settings", response_model=TiSettings)
def get_settings(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ADMIN_ONLY)):
    return _settings(db, current_user.tenant_key)


@router.put("/settings", response_model=TiSettings)
def put_settings(body: TiSettings, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ADMIN_ONLY)):
    """VirusTotal is opt-in per tenant (default off): with it off no hash is ever sent."""
    db.execute(text(
        "INSERT INTO ti_tenant_settings (tenant_key, vt_enabled, vt_daily_budget, updated_at, updated_by) "
        "VALUES (:t, :e, :b, now(), :u) ON CONFLICT (tenant_key) DO UPDATE SET vt_enabled = EXCLUDED.vt_enabled, "
        "vt_daily_budget = EXCLUDED.vt_daily_budget, updated_at = now(), updated_by = EXCLUDED.updated_by"),
        {"t": current_user.tenant_key, "e": body.vt_enabled, "b": body.vt_daily_budget, "u": str(current_user.user_id)})
    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id, action="ti_settings_changed",
                 target=f"vt_enabled={body.vt_enabled},vt_daily_budget={body.vt_daily_budget}", outcome="success")
    return _settings(db, current_user.tenant_key)


@router.post("/virustotal/lookups")
def lookup(body: LookupRequest, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    """200 with the cached verdict, or 202 queued / budget_reached (the worker answers it
    when the budget allows; poll GET /api/ti/virustotal/{sha256}). Audited either way."""
    sha256 = _sha256(body.sha256)
    settings = _settings(db, current_user.tenant_key)
    audit = lambda outcome: append_entry(  # noqa: E731
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id, action="virustotal_lookup",
        target=sha256, outcome=outcome)
    if not settings.vt_enabled:
        audit("refused:disabled")
        raise HTTPException(status_code=409, detail="VirusTotal is not enabled for this tenant")
    v = _verdict(db, current_user.tenant_key, sha256)
    if v:
        audit("cached")
        return {"status": "cached", "verdict": v.model_dump(mode="json")}
    db.execute(text(
        "INSERT INTO vt_requests (tenant_key, sha256, origin, requested_by) SELECT :t, :h, 'api', :u "
        "WHERE NOT EXISTS (SELECT 1 FROM vt_requests WHERE tenant_key = :t AND sha256 = :h AND state = 'pending')"),
        {"t": current_user.tenant_key, "h": sha256, "u": str(current_user.user_id)})
    state = _queue_state(db, current_user.tenant_key, settings)
    audit(state)                                         # commits the request with the audit entry
    return JSONResponse(status_code=202, content={"status": state, "sha256": sha256})


@router.get("/virustotal/{sha256}")
def get_lookup(sha256: str, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    sha256 = _sha256(sha256)
    v = _verdict(db, current_user.tenant_key, sha256)
    if v:
        return {"status": "cached", "verdict": v.model_dump(mode="json")}
    pending = db.execute(text("SELECT 1 FROM vt_requests WHERE tenant_key = :t AND sha256 = :h AND state = 'pending'"),
                         {"t": current_user.tenant_key, "h": sha256}).first()
    if pending:
        return {"status": _queue_state(db, current_user.tenant_key, _settings(db, current_user.tenant_key)), "sha256": sha256}
    raise HTTPException(status_code=404, detail="no verdict and no pending lookup for this hash")
