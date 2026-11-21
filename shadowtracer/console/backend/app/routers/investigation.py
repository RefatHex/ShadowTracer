"""Phase 7.7: analyst-triggered LLM investigation endpoints (read-only, advisory).

POST /api/incidents/{id}/investigate   analyst+  run the agent, store + return the result
GET  /api/incidents/{id}/investigation analyst+  the latest stored result (or null)
GET  /api/investigation/settings        analyst+  this tenant's external-LLM opt-in
PUT  /api/investigation/settings        admin     toggle external-LLM opt-in (audited)

Budgets (per tenant per UTC day): investigation count + token cap. One running investigation per
incident at a time (advisory lock). The LLM has no state-changing tool and is tenant/role-scoped via
the same read handlers the analyst uses. If the LLM is down, the evidence pack is still returned (200).
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ADMIN_ONLY, ANALYST_OR_ABOVE, CurrentUser
from ..investigation.agent import run_llm
from ..investigation.gather import gather_core
from ..investigation.llm import LLMClient, LLMUnavailable

router = APIRouter(prefix="/api", tags=["investigation"])


def _client(settings: Settings) -> LLMClient:
    return LLMClient(base_url=settings.llm_base_url, model=settings.llm_model, api_key=settings.llm_api_key,
                     timeout_seconds=settings.llm_timeout_seconds, num_ctx=settings.llm_num_ctx,
                     max_tokens=settings.llm_max_tokens)


def _budget(db: Session, tenant: str, settings: Settings) -> None:
    row = db.execute(text(
        "SELECT count(*) n, COALESCE(sum(tokens), 0) t FROM incident_investigations "
        "WHERE tenant_key = :t AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')"),
        {"t": tenant}).mappings().first()
    if row["n"] >= settings.investigation_daily_limit:
        raise HTTPException(status_code=429,
                            detail=f"daily investigation limit reached ({settings.investigation_daily_limit}/day); try tomorrow")
    if row["t"] >= settings.investigation_token_daily_limit:
        raise HTTPException(status_code=429,
                            detail=f"daily investigation token budget reached ({settings.investigation_token_daily_limit}); try tomorrow")


@router.post("/incidents/{incident_id}/investigate")
def investigate(incident_id: int, settings: Settings = Depends(get_settings), db: Session = Depends(get_db),
                current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    tenant = current_user.tenant_key
    _budget(db, tenant, settings)
    # one running investigation per incident at a time (transaction-scoped advisory lock)
    got = db.execute(text("SELECT pg_try_advisory_xact_lock(:k1, :k2)"),
                     {"k1": 7700, "k2": incident_id}).scalar()
    if not got:
        raise HTTPException(status_code=409, detail="an investigation is already running for this incident")

    evidence, meta = gather_core(db, current_user, settings, incident_id)   # 404 for cross-tenant
    client = _client(settings)
    t0 = time.monotonic()
    try:
        result = run_llm(client, db, current_user, settings, incident_id, evidence, meta)
    except LLMUnavailable as e:
        append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
                     action="investigate", target=f"incident:{incident_id}", outcome="llm_unavailable")
        return {"status": "llm_unavailable", "incident_id": incident_id, "evidence": evidence,
                "message": "The investigation model is unavailable. The evidence pack is shown; "
                           "no summary could be generated.", "detail": str(e)}
    latency_ms = int((time.monotonic() - t0) * 1000)
    result["latency_ms"] = latency_ms
    db.execute(text(
        "INSERT INTO incident_investigations (tenant_key, incident_id, result, model, prompt_version, "
        "latency_ms, tokens, created_by) VALUES (:t, :i, CAST(:r AS jsonb), :m, :p, :l, :tok, :by)"),
        {"t": tenant, "i": incident_id, "r": _json(result), "m": result["model"],
         "p": result["prompt_version"], "l": latency_ms, "tok": result["tokens"], "by": str(current_user.user_id)})
    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
                 action="investigate", target=f"incident:{incident_id}", outcome="success")
    db.commit()
    return {"status": "ok", **result, "latency_ms": latency_ms}


@router.get("/incidents/{incident_id}/investigation")
def latest_investigation(incident_id: int, db: Session = Depends(get_db),
                         current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    row = db.execute(text(
        "SELECT result, model, prompt_version, latency_ms, tokens, created_by, created_at "
        "FROM incident_investigations WHERE tenant_key = :t AND incident_id = :i "
        "ORDER BY created_at DESC LIMIT 1"),
        {"t": current_user.tenant_key, "i": incident_id}).mappings().first()
    if row is None:
        return None
    r = dict(row["result"])
    r.update({"latency_ms": row["latency_ms"], "created_by": row["created_by"],
              "created_at": row["created_at"].isoformat(), "status": "ok"})
    return r


class InvestigationSettings(BaseModel):
    external_llm_enabled: bool


@router.get("/investigation/settings", response_model=InvestigationSettings)
def get_investigation_settings(db: Session = Depends(get_db),
                               current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    row = db.execute(text("SELECT external_llm_enabled FROM tenant_investigation_settings WHERE tenant_key = :t"),
                     {"t": current_user.tenant_key}).mappings().first()
    return InvestigationSettings(external_llm_enabled=bool(row["external_llm_enabled"]) if row else False)


@router.put("/investigation/settings", response_model=InvestigationSettings)
def put_investigation_settings(body: InvestigationSettings, db: Session = Depends(get_db),
                               current_user: CurrentUser = Depends(ADMIN_ONLY)):
    db.execute(text(
        "INSERT INTO tenant_investigation_settings (tenant_key, external_llm_enabled, updated_by, updated_at) "
        "VALUES (:t, :e, :by, now()) ON CONFLICT (tenant_key) DO UPDATE SET "
        "external_llm_enabled = EXCLUDED.external_llm_enabled, updated_by = EXCLUDED.updated_by, updated_at = now()"),
        {"t": current_user.tenant_key, "e": body.external_llm_enabled, "by": str(current_user.user_id)})
    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id, action="investigation_settings",
                 target=f"external_llm_enabled={body.external_llm_enabled}", outcome="success")
    db.commit()
    return body


def _json(obj) -> str:
    import json
    return json.dumps(obj, default=str)
