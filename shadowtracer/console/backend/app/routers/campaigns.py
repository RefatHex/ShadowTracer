"""Phase 7.6 follow-up: a campaigns list so the console can surface the campaign relationship graph
(the graph endpoint and GraphView existed; nothing navigated to a campaign). Tenant from the token
only. Read-only; any authenticated role may list (the graph itself is analyst+, enforced by
routers/graph.py and GraphView)."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..deps import get_db
from ..rbac import ALL_ROLES, CurrentUser

router = APIRouter(prefix="/api", tags=["campaigns"])


class Campaign(BaseModel):
    id: int
    actor_type: str
    actor_value: str
    incident_count: int
    first_seen: str | None
    last_seen: str | None


@router.get("/campaigns", response_model=list[Campaign])
def list_campaigns(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    """The tenant's campaigns, the ones that link the most incidents first (a shared attacker across
    many incidents is what the campaign graph is for)."""
    rows = db.execute(text(
        "SELECT id, actor_type, actor_value, incident_count, first_seen, last_seen "
        "FROM campaigns WHERE tenant_key = :t AND incident_count > 1 "
        "ORDER BY incident_count DESC, last_seen DESC LIMIT 50"),
        {"t": current_user.tenant_key}).mappings().all()
    return [Campaign(id=r["id"], actor_type=r["actor_type"], actor_value=r["actor_value"],
                     incident_count=r["incident_count"],
                     first_seen=r["first_seen"].isoformat() if r["first_seen"] else None,
                     last_seen=r["last_seen"].isoformat() if r["last_seen"] else None) for r in rows]
