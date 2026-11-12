"""Phase 5A Step 3: admin-settable per-agent metadata (role_tag, os_family)
that feeds the fingerprint's target_class - real Wazuh 4.14.8 alerts carry
no OS info at all, so this has to be admin-set rather than derived from
the alert stream (see shadowtracer/correlate's models.py). Changing
either one changes which fingerprint a future incident on that agent
computes to, so every change is audited, per spec."""

import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..deps import get_db
from ..models import agent_role_tags
from ..rbac import ADMIN_ONLY, ALL_ROLES, CurrentUser

router = APIRouter(prefix="/api", tags=["agents"])


class AgentDrift(BaseModel):
    # Phase 7.2: River ADWIN behaviour-drift events for one agent (advisory).
    metric: str
    before_value: float
    after_value: float
    magnitude: float
    window_start: datetime.datetime


@router.get("/agents/{agent_id}/drift", response_model=list[AgentDrift])
def agent_drift(agent_id: str, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    """Recent behaviour-drift events for this agent (advisory; the drift-monitor writes them)."""
    rows = db.execute(text(
        "SELECT metric, before_value, after_value, magnitude, window_start FROM drift_events "
        "WHERE tenant_key = :t AND entity_type = 'agent' AND entity = :a ORDER BY window_start DESC LIMIT 20"),
        {"t": current_user.tenant_key, "a": agent_id}).mappings().all()
    return [AgentDrift(**r) for r in rows]


class AgentRoleTagRequest(BaseModel):
    role_tag: str | None = None
    os_family: str | None = None


@router.put("/agents/{agent_id}/role-tag")
def set_agent_role_tag(
    agent_id: str,
    body: AgentRoleTagRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ADMIN_ONLY),
):
    db.execute(
        pg_insert(agent_role_tags)
        .values(tenant_key=current_user.tenant_key, agent_id=agent_id, role_tag=body.role_tag, os_family=body.os_family)
        .on_conflict_do_update(
            index_elements=["tenant_key", "agent_id"],
            set_={"role_tag": body.role_tag, "os_family": body.os_family, "updated_at": func.now()},
        )
    )
    append_entry(
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action="agent_role_tag_changed", target=f"{agent_id}:{body.role_tag}:{body.os_family}", outcome="success",
    )
    return {"status": "ok"}
