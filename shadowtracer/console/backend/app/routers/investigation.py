"""Phase 7.7: analyst-triggered LLM investigation endpoints (read-only, advisory).

POST /api/incidents/{id}/investigate   analyst+  QUEUE an investigation (returns 202-style {running};
                                                 the ~19 s agent runs in the background, never tying up
                                                 the request). Poll the GET below for the result.
GET  /api/incidents/{id}/investigation analyst+  latest stored result/status (running|ok|llm_unavailable
                                                 |evidence_too_large|error), or null
GET  /api/investigation/settings        analyst+  this tenant's external-LLM opt-in
PUT  /api/investigation/settings        admin     toggle external-LLM opt-in (audited)

Budgets (per tenant per UTC day): investigation count + token cap. One running investigation per
incident at a time (partial unique index). The LLM has no state-changing tool and is tenant/role-scoped
via the same read handlers the analyst uses. If the LLM is down, the evidence pack is still stored (the
GET returns status llm_unavailable, never a 5xx).
"""
from __future__ import annotations

import time

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ADMIN_ONLY, ANALYST_OR_ABOVE, CurrentUser
from ..investigation.agent import PROMPT_VERSION, run_llm
from ..investigation.gather import gather_core
from ..investigation.llm import LLMClient, LLMUnavailable, LLMPromptTruncated
from ..routers.incidents import get_incident

router = APIRouter(prefix="/api", tags=["investigation"])


def _client(settings: Settings) -> LLMClient:
    return LLMClient(base_url=settings.llm_base_url, model=settings.llm_model, api_key=settings.llm_api_key,
                     timeout_seconds=settings.llm_timeout_seconds, num_ctx=settings.llm_num_ctx,
                     max_tokens=settings.llm_max_tokens, keep_alive=settings.llm_keep_alive)


def _run_job(session_factory, settings: Settings, user: CurrentUser, incident_id: int, row_id: int) -> None:
    """Background worker: gather evidence + run the LLM + verify, then store the outcome on the
    pre-inserted 'running' row. Never raises - any failure is recorded as a status so the row never
    stays stuck on 'running'."""
    db = session_factory()
    status, message, latency_ms, tokens = "error", "investigation failed", 0, 0
    result: dict = {"incident_id": incident_id, "evidence": []}
    try:
        evidence, meta = gather_core(db, user, settings, incident_id)
        result["evidence"] = evidence
        t0 = time.monotonic()
        try:
            result = run_llm(_client(settings), db, user, settings, incident_id, evidence, meta)
            latency_ms, tokens = int((time.monotonic() - t0) * 1000), result["tokens"]
            if any((result.get("sections") or {}).values()):
                status = "ok"
            else:                                    # model produced no usable text - evidence still shown
                status = "empty_summary"
                message = "The model returned no summary. The evidence pack is shown below."
        except LLMUnavailable:
            status = "llm_unavailable"
            message = ("The investigation model is unavailable. The evidence pack is shown; "
                       "no summary could be generated.")
            result = {"incident_id": incident_id, "evidence": evidence}
        except LLMPromptTruncated as e:
            status, message = "evidence_too_large", str(e)
            result = {"incident_id": incident_id, "evidence": evidence}
    except Exception as e:                       # noqa: BLE001 - advisory; record and degrade
        status, message = "error", f"investigation failed: {type(e).__name__}"
    try:
        db.execute(text(
            "UPDATE incident_investigations SET status=:s, result=CAST(:r AS jsonb), message=:m, "
            "latency_ms=:l, tokens=:tok, model=COALESCE(:model, model) WHERE id=:id"),
            {"s": status, "r": _json(result), "m": message, "l": latency_ms, "tok": tokens,
             "model": result.get("model"), "id": row_id})
        append_entry(db, actor=str(user.user_id), tenant_id=user.tenant_id, action="investigate",
                     target=f"incident:{incident_id}", outcome=status)
        db.commit()
    finally:
        db.close()


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


@router.post("/incidents/{incident_id}/investigate", status_code=202)
def investigate(incident_id: int, request: Request, background: BackgroundTasks,
                settings: Settings = Depends(get_settings), db: Session = Depends(get_db),
                current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    """Queue an investigation and return immediately; the ~19 s agent runs in the background. Poll
    GET /api/incidents/{id}/investigation for the result."""
    tenant = current_user.tenant_key
    _budget(db, tenant, settings)
    get_incident(incident_id, settings=settings, db=db, current_user=current_user)  # 404 cross-tenant/missing
    # reap a zombie 'running' row (worker died mid-run) so it can never block new runs forever
    db.execute(text(
        "UPDATE incident_investigations SET status='error', message='investigation timed out' "
        "WHERE tenant_key=:t AND incident_id=:i AND status='running' "
        "AND created_at < now() - make_interval(secs => :to)"),
        {"t": tenant, "i": incident_id, "to": settings.llm_timeout_seconds * 3})
    try:
        row_id = db.execute(text(
            "INSERT INTO incident_investigations (tenant_key, incident_id, status, model, prompt_version, "
            "latency_ms, created_by) VALUES (:t, :i, 'running', :m, :p, 0, :by) RETURNING id"),
            {"t": tenant, "i": incident_id, "m": settings.llm_model, "p": PROMPT_VERSION,
             "by": str(current_user.user_id)}).scalar()
        db.commit()
    except IntegrityError:                       # partial unique index: already one running
        db.rollback()
        raise HTTPException(status_code=409, detail="an investigation is already running for this incident")
    background.add_task(_run_job, request.app.state.session_factory, settings, current_user,
                        incident_id, row_id)
    return {"status": "running", "incident_id": incident_id, "id": row_id}


@router.get("/incidents/{incident_id}/investigation")
def latest_investigation(incident_id: int, db: Session = Depends(get_db),
                         current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    row = db.execute(text(
        "SELECT result, status, message, model, prompt_version, latency_ms, tokens, created_by, created_at "
        "FROM incident_investigations WHERE tenant_key = :t AND incident_id = :i "
        "ORDER BY created_at DESC LIMIT 1"),
        {"t": current_user.tenant_key, "i": incident_id}).mappings().first()
    if row is None:
        return None
    r = dict(row["result"]) if row["result"] else {"incident_id": incident_id, "evidence": []}
    r.update({"status": row["status"], "message": row["message"], "model": row["model"],
              "prompt_version": row["prompt_version"], "latency_ms": row["latency_ms"],
              "tokens": row["tokens"], "created_by": row["created_by"],
              "created_at": row["created_at"].isoformat()})
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
