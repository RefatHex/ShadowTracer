"""Phase 7.5: top-k similar PAST incidents for an incident (analyst+). Similarity is by attack shape
(structured-field embedding in Qdrant, written by the ml-enricher). Tenant from the token only; the
Qdrant query is tenant-filtered and the Postgres detail lookup is tenant-scoped, so a cross-tenant id
returns 404 and never leaks another tenant's incidents."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import qdrant_similar
from ..deps import get_db
from ..rbac import ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api", tags=["similar"])


class SimilarIncident(BaseModel):
    incident_id: int
    score: float
    agent_id: str
    correlation_basis: str | None
    rule_groups: list[str]
    max_level: int
    state: str
    triage_status: str | None     # how it was resolved: acknowledged / escalated / false_positive
    priority: int | None
    closed_at: str | None


@router.get("/incidents/{incident_id}/similar", response_model=list[SimilarIncident])
def similar_incidents(incident_id: int, k: int = Query(5, ge=1, le=20),
                      db: Session = Depends(get_db), current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    tenant = current_user.tenant_key
    exists = db.execute(text("SELECT 1 FROM incidents WHERE id = :i AND tenant_key = :t"),
                        {"i": incident_id, "t": tenant}).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="incident not found")   # cross-tenant -> 404
    hits = qdrant_similar.similar(tenant, incident_id, k)
    if not hits:
        return []
    by_id = {h["incident_id"]: h["score"] for h in hits}
    rows = db.execute(text(
        "SELECT id, agent_id, correlation_basis, rule_groups, max_level, state, triage_status, priority, closed_at "
        "FROM incidents WHERE tenant_key = :t AND id = ANY(:ids)"),
        {"t": tenant, "ids": list(by_id)}).mappings().all()
    out = [SimilarIncident(
        incident_id=r["id"], score=by_id[r["id"]], agent_id=r["agent_id"],
        correlation_basis=r["correlation_basis"], rule_groups=list(r["rule_groups"] or []),
        max_level=r["max_level"], state=r["state"], triage_status=r["triage_status"], priority=r["priority"],
        closed_at=r["closed_at"].isoformat() if r["closed_at"] else None) for r in rows]
    out.sort(key=lambda s: s.score, reverse=True)   # Qdrant order, by score
    return out
