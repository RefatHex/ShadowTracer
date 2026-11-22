"""SOAR console API (Phase 9 G/H): approvals queue, approve/deny, undo, action history.
Tenant-scoped, analyst+ (admin for disable_account/quarantine approvals — enforced in approvals.py).
Four-eyes and reason-required are enforced in the logic layer. A cross-tenant action id -> 404.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..rbac import ANALYST_OR_ABOVE, CurrentUser
from ..deps import get_db
from ..soar import approvals

router = APIRouter(prefix="/api/soar", tags=["soar"])


class Decision(BaseModel):
    reason: str


def _load(db, user: CurrentUser, action_id: int) -> dict:
    action = approvals.get_action(db, user.tenant_key, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return action


@router.get("/approvals")
def pending(db: Session = Depends(get_db), user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    return {"pending": approvals.list_pending(db, user.tenant_key)}


@router.get("/actions")
def history(limit: int = 100, db: Session = Depends(get_db),
            user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    from sqlalchemy import select
    from ..soar.models import soar_actions
    rows = db.execute(select(soar_actions).where(soar_actions.c.tenant_key == user.tenant_key)
                      .order_by(soar_actions.c.created_at.desc()).limit(min(limit, 500))).mappings().all()
    return {"actions": [dict(r) for r in rows]}


@router.post("/approvals/{action_id}/approve")
def approve(action_id: int, body: Decision, db: Session = Depends(get_db),
            user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    action = _load(db, user, action_id)
    try:
        return approvals.approve(db, user.tenant_key, user.tenant_id, action,
                                 str(user.user_id), user.role, body.reason)
    except approvals.ApprovalError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.post("/approvals/{action_id}/deny")
def deny(action_id: int, body: Decision, db: Session = Depends(get_db),
         user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    action = _load(db, user, action_id)
    try:
        return approvals.deny(db, user.tenant_key, user.tenant_id, action,
                              str(user.user_id), user.role, body.reason)
    except approvals.ApprovalError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.post("/actions/{action_id}/undo")
def undo(action_id: int, db: Session = Depends(get_db),
         user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    action = _load(db, user, action_id)
    try:
        return approvals.undo(db, user.tenant_key, user.tenant_id, action, str(user.user_id), user.role)
    except approvals.ApprovalError as e:
        raise HTTPException(status_code=e.code, detail=e.message)
