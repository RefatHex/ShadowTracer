"""Phase 5A Step 3: admin-settable per-agent metadata (role_tag, os_family)
that feeds the fingerprint's target_class - real Wazuh 4.14.8 alerts carry
no OS info at all, so this has to be admin-set rather than derived from
the alert stream (see shadowtracer/correlate's models.py). Changing
either one changes which fingerprint a future incident on that agent
computes to, so every change is audited, per spec."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..deps import get_db
from ..models import agent_role_tags
from ..rbac import ADMIN_ONLY, CurrentUser

router = APIRouter(prefix="/api", tags=["agents"])


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
