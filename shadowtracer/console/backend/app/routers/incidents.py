"""Phase 5A Step 5: incident list/detail and triage actions. Every query
is scoped to current_user.tenant_key (never a path/query parameter) -
same rule as alerts.py. Viewers can read but never triage (ALL_ROLES on
the GETs, ANALYST_OR_ABOVE on the actions that change state)."""

import datetime

import clickhouse_connect
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from .. import incidents as incidents_logic
from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..models import incident_alerts, incidents, tenant_alert_settings
from ..rarity import warmup_status
from ..rbac import ADMIN_ONLY, ALL_ROLES, ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api", tags=["incidents"])

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

ALERT_COLUMNS = [
    "time", "cluster_node", "alert_id", "agent_id", "agent_name",
    "rule_id", "rule_level", "rule_description", "message",
]


class IncidentSummary(BaseModel):
    id: int
    agent_id: str
    correlation_basis: str
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    alert_count: int
    max_level: int
    state: str
    triage_status: str
    fingerprint_key: str | None
    # Phase 5B Step 3: a flag, never a replacement for the incident - every
    # other field above is populated exactly as before regardless of this.
    rare_pattern_flag: bool
    prior_occurrences: int | None
    rare_pattern_reason: str | None


class IncidentsPage(BaseModel):
    incidents: list[IncidentSummary]
    next_cursor: str | None


class IncidentAlert(BaseModel):
    time: datetime.datetime
    cluster_node: str
    alert_id: str
    agent_id: str
    agent_name: str
    rule_id: str
    rule_level: int
    rule_description: str
    message: str


class IncidentDetail(IncidentSummary):
    rule_ids: list[str]
    rule_groups: list[str]
    mitre_ids: list[str]
    source_ips: list[str]
    source_ip_total: int
    users: list[str]
    user_total: int
    closed_at: datetime.datetime | None
    alerts: list[IncidentAlert]


class TriageRequest(BaseModel):
    action: str  # "acknowledge" | "escalate" | "false_positive"


class TriageResponse(BaseModel):
    triage_status: str
    suppression_state_changed_to: str | None


class CommentRequest(BaseModel):
    text: str


def _get_ch_client(settings: Settings):
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host, port=settings.clickhouse_port,
        username=settings.clickhouse_user, password=settings.clickhouse_password,
        database=settings.clickhouse_database,
    )


def _encode_cursor(first_seen: datetime.datetime, incident_id: int) -> str:
    return f"{first_seen.isoformat()}|{incident_id}"


def _decode_cursor(cursor: str) -> tuple[str, int]:
    time_part, id_part = cursor.split("|", 1)
    return time_part, int(id_part)


class WarmupStatus(BaseModel):
    complete: bool
    days_elapsed: int
    warmup_days: int
    incident_count: int
    warmup_min_incidents: int


@router.get("/rare-pattern-warmup-status", response_model=WarmupStatus)
def get_rare_pattern_warmup_status(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    """Phase 5B Step 3: "warming up (day X of 7, Y of N incidents)" -
    read-only, scoped to the caller's own tenant only (same rule as every
    other query in this router)."""
    return WarmupStatus(**warmup_status(db, current_user.tenant_key))


class WarmupOverrideRequest(BaseModel):
    warmup_days: int = Field(ge=0)
    warmup_min_incidents: int = Field(ge=0)


@router.put("/rare-pattern-warmup-override", response_model=WarmupStatus)
def set_rare_pattern_warmup_override(
    body: WarmupOverrideRequest, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ADMIN_ONLY),
):
    """Phase 5C Step 0: admin-only and audited - this is a per-tenant
    override of WHEN rare-pattern alerting starts trusting a tenant's
    history at all (see rarity.py's warmup_status), not a cosmetic
    setting; loosening it changes which incidents get flagged rare."""
    db.execute(
        pg_insert(tenant_alert_settings)
        .values(
            tenant_key=current_user.tenant_key,
            rare_alert_warmup_days=body.warmup_days,
            rare_alert_warmup_min_incidents=body.warmup_min_incidents,
        )
        .on_conflict_do_update(
            index_elements=["tenant_key"],
            set_={
                "rare_alert_warmup_days": body.warmup_days,
                "rare_alert_warmup_min_incidents": body.warmup_min_incidents,
                "updated_at": func.now(),
            },
        )
    )
    append_entry(
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action="rare_pattern_warmup_override_changed",
        target=f"warmup_days={body.warmup_days}:warmup_min_incidents={body.warmup_min_incidents}",
        outcome="success",
    )
    return WarmupStatus(**warmup_status(db, current_user.tenant_key))


@router.get("/incidents", response_model=IncidentsPage)
def list_incidents(
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: str | None = None,
    state: str | None = Query(default=None, pattern="^(open|closed)$"),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ALL_ROLES),
):
    query = select(incidents).where(incidents.c.tenant_key == current_user.tenant_key)
    if state:
        query = query.where(incidents.c.state == state)
    if cursor:
        cursor_time, cursor_id = _decode_cursor(cursor)
        query = query.where((incidents.c.first_seen, incidents.c.id) < (cursor_time, cursor_id))
    query = query.order_by(incidents.c.first_seen.desc(), incidents.c.id.desc()).limit(limit)

    rows = db.execute(query).mappings().all()
    items = [IncidentSummary(**row) for row in rows]
    next_cursor = _encode_cursor(items[-1].first_seen, items[-1].id) if len(items) == limit else None
    return IncidentsPage(incidents=items, next_cursor=next_cursor)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: int,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ALL_ROLES),
):
    row = db.execute(
        select(incidents).where(incidents.c.id == incident_id, incidents.c.tenant_key == current_user.tenant_key)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")

    memberships = db.execute(
        select(incident_alerts.c.node, incident_alerts.c.alert_id)
        .where(incident_alerts.c.incident_id == incident_id)
    ).all()

    alerts: list[IncidentAlert] = []
    if memberships:
        ch_client = _get_ch_client(settings)
        try:
            # Alert content is never duplicated into Postgres (Step 2:
            # "incidents never delete or hide alerts" - ClickHouse stays
            # the one source of truth) - fetched here by the exact
            # (node, alert_id) pairs this incident's membership rows name.
            pairs = ", ".join(f"('{node}', '{alert_id}')" for node, alert_id in memberships)
            query = f"""
                SELECT {', '.join(ALERT_COLUMNS)}
                FROM events
                WHERE tenant_id = {{tenant_id:String}} AND (cluster_node, alert_id) IN ({pairs})
                ORDER BY time ASC
            """
            result = ch_client.query(query, parameters={"tenant_id": current_user.tenant_key})
            alerts = [IncidentAlert(**dict(zip(ALERT_COLUMNS, r))) for r in result.result_rows]
        finally:
            ch_client.close()

    return IncidentDetail(**row, alerts=alerts)


@router.post("/incidents/{incident_id}/triage", response_model=TriageResponse)
def triage_incident(
    incident_id: int,
    body: TriageRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ANALYST_OR_ABOVE),
):
    if body.action not in incidents_logic.TRIAGE_STATUS_FOR_ACTION:
        raise HTTPException(status_code=400, detail="invalid action")
    try:
        result = incidents_logic.apply_triage(
            db, current_user.tenant_key, incident_id, body.action, current_user.user_id,
        )
    except incidents_logic.IncidentNotFound:
        raise HTTPException(status_code=404, detail="incident not found")

    append_entry(
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action=f"incident_triage:{body.action}", target=str(incident_id), outcome="success",
    )
    if result["suppression_state_changed_to"]:
        append_entry(
            db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
            action="fingerprint_suppression_proposed", target=result["fingerprint_key"], outcome="success",
        )
    return TriageResponse(
        triage_status=result["triage_status"], suppression_state_changed_to=result["suppression_state_changed_to"],
    )


@router.post("/incidents/{incident_id}/comment")
def comment_on_incident(
    incident_id: int,
    body: CommentRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ANALYST_OR_ABOVE),
):
    row = db.execute(
        select(incidents.c.id).where(incidents.c.id == incident_id, incidents.c.tenant_key == current_user.tenant_key)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")

    # Comments are audit-only - no mutable "notes" column on incidents
    # itself (Step 2 doesn't call for one), the comment text travels as
    # the audit row's target, same storage the rest of this project
    # already trusts for an append-only record.
    append_entry(
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action="incident_comment", target=body.text, outcome="success",
    )
    return {"status": "ok"}
