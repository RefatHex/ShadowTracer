"""Phase 5A Step 5: incident list/detail and triage actions. Every query
is scoped to current_user.tenant_key (never a path/query parameter) -
same rule as alerts.py. Viewers can read but never triage (ALL_ROLES on
the GETs, ANALYST_OR_ABOVE on the actions that change state)."""

import datetime

import clickhouse_connect
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from .. import incidents as incidents_logic
from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..models import incident_alerts, incidents, tenant_alert_settings
from ..rarity import get_tenant_prior_occurrence_threshold, warmup_status
from ..rbac import ADMIN_ONLY, ALL_ROLES, ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api", tags=["incidents"])

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
# A hard cap on how many of an incident's alerts any one request loads into memory. A real incident
# can have >100k alerts (e.g. an SSH brute force); loading them all OOM-killed the 160 MiB console
# worker (a 502). The detail endpoint returns the first page; the rest come from /incidents/{id}/alerts
# by keyset cursor (alert_time, id). No endpoint ever materialises more than this many alert rows.
ALERT_PAGE_SIZE = 200

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
    # Phase 6.1c: highest TI match confidence (ti-matcher) and the priority derived from
    # it - GREATEST(max_level, 12 if >= 75, 8 if >= 50). None/max_level without matches.
    ti_confidence: int | None = None
    priority: int
    # Phase 6.5 A1: a FIM file in this incident is a known-good file (CIRCL hashlookup); priority is
    # lowered and no TI alert fires. The source is shown as "known file (source: NSRL/…)".
    known_good: bool = False
    known_good_source: str | None = None
    known_good_safe: bool = False
    known_good_note: str | None = None
    tor_exit_ips: list[str] = []
    # Phase 6.5 A3: CVE enrichment (KEV = actively exploited -> priority floored; EPSS = exploit prob)
    cve_ids: list[str] = []
    kev_cve_ids: list[str] = []
    max_epss: float | None = None


class TiSource(BaseModel):
    name: str
    reference_url: str | None
    source_info: str | None


class TiVerdict(BaseModel):
    status: str
    malicious: int
    total: int
    labels: list[str]
    last_analysis: datetime.datetime | None
    permalink: str


class TiMatch(BaseModel):
    id: int
    alert_id: str
    node: str
    rule_id: str
    field: str
    observable_type: str
    observable: str
    ioc_id: int
    ioc_type: str
    ioc_value: str
    sources: list[str]
    source_details: list[TiSource] = []
    confidence: int
    origin: str                      # matcher | virustotal | retro
    tlp: str
    labels: list[str]
    mitre: list[str]
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    false_positive: bool
    virustotal: TiVerdict | None = None


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


class AlertCursor(BaseModel):
    # Keyset position for paging an incident's alerts: everything after (alert_time, id).
    after_time: datetime.datetime
    after_id: int


class AlertPage(BaseModel):
    alerts: list[IncidentAlert]
    next: AlertCursor | None = None   # null = last page


class DriftEvent(BaseModel):
    # Phase 7.2: advisory behaviour-drift note for this incident's agent.
    metric: str
    before_value: float
    after_value: float
    magnitude: float
    window_start: datetime.datetime


class IncidentDetail(IncidentSummary):
    rule_ids: list[str]
    rule_groups: list[str]
    mitre_ids: list[str]
    source_ips: list[str]
    source_ip_total: int
    users: list[str]
    user_total: int
    closed_at: datetime.datetime | None
    alerts: list[IncidentAlert]           # first page only (<= ALERT_PAGE_SIZE); total is alert_count
    alerts_next: AlertCursor | None = None   # cursor for /incidents/{id}/alerts, null if all alerts fit one page
    ti_matches: list[TiMatch] = []
    drift_events: list[DriftEvent] = []


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
    # Phase 5C Step 0 follow-up: "rare" means NOVEL here - flagged when
    # prior_count <= this, defaulting to 0 (strictly "first seen for this
    # tenant"). Per-tenant configurable the same way warmup_days/
    # warmup_min_incidents are.
    prior_occurrence_threshold: int


def _warmup_status_response(db: Session, tenant_key: str) -> WarmupStatus:
    return WarmupStatus(
        **warmup_status(db, tenant_key),
        prior_occurrence_threshold=get_tenant_prior_occurrence_threshold(db, tenant_key),
    )


@router.get("/rare-pattern-warmup-status", response_model=WarmupStatus)
def get_rare_pattern_warmup_status(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    """Phase 5B Step 3: "warming up (day X of 7, Y of N incidents)" -
    read-only, scoped to the caller's own tenant only (same rule as every
    other query in this router)."""
    return _warmup_status_response(db, current_user.tenant_key)


class WarmupOverrideRequest(BaseModel):
    warmup_days: int = Field(ge=0)
    warmup_min_incidents: int = Field(ge=0)
    prior_occurrence_threshold: int = Field(ge=0, default=0)


@router.put("/rare-pattern-warmup-override", response_model=WarmupStatus)
def set_rare_pattern_warmup_override(
    body: WarmupOverrideRequest, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ADMIN_ONLY),
):
    """Phase 5C Step 0: admin-only and audited - this is a per-tenant
    override of WHEN rare-pattern alerting starts trusting a tenant's
    history at all (see rarity.py's warmup_status) and of what counts as
    "first seen" (prior_occurrence_threshold) - not a cosmetic setting;
    loosening either changes which incidents get flagged."""
    db.execute(
        pg_insert(tenant_alert_settings)
        .values(
            tenant_key=current_user.tenant_key,
            rare_alert_warmup_days=body.warmup_days,
            rare_alert_warmup_min_incidents=body.warmup_min_incidents,
            rare_alert_prior_occurrence_threshold=body.prior_occurrence_threshold,
        )
        .on_conflict_do_update(
            index_elements=["tenant_key"],
            set_={
                "rare_alert_warmup_days": body.warmup_days,
                "rare_alert_warmup_min_incidents": body.warmup_min_incidents,
                "rare_alert_prior_occurrence_threshold": body.prior_occurrence_threshold,
                "updated_at": func.now(),
            },
        )
    )
    append_entry(
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action="rare_pattern_warmup_override_changed",
        target=(
            f"warmup_days={body.warmup_days}:warmup_min_incidents={body.warmup_min_incidents}:"
            f"prior_occurrence_threshold={body.prior_occurrence_threshold}"
        ),
        outcome="success",
    )
    return _warmup_status_response(db, current_user.tenant_key)


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

    # Only the FIRST page of alerts (keyset on alert_time, id). A large incident can have >100k
    # alerts; loading them all OOM-killed this worker. The rest come from /incidents/{id}/alerts.
    page = _alert_page(db, settings, incident_id, current_user.tenant_key)

    # Phase 6.4: every value below comes from feeds or alerts - rendered as text only.
    rows = db.execute(text(
        "SELECT t.id, t.alert_id, t.node, t.rule_id, t.field, t.observable_type, t.observable, t.ioc_id, i.type AS ioc_type, "
        " t.ioc_value, t.sources, t.confidence, t.origin, i.tlp, i.labels, i.mitre, i.valid_from AS first_seen, i.last_seen, "
        " EXISTS (SELECT 1 FROM ti_feedback f WHERE f.incident_ti_id = t.id) AS false_positive, "
        " COALESCE((SELECT json_agg(json_build_object('name', src.name, 'reference_url', s.reference_url, "
        "   'source_info', s.source_info) ORDER BY src.name) FROM ioc_sightings s JOIN ti_sources src ON src.id = s.source_id "
        "   WHERE s.ioc_id = t.ioc_id AND s.revoked_at IS NULL AND (src.tenant_key IS NULL OR src.tenant_key = :t)), '[]') "
        "   AS source_details, "
        " (SELECT json_build_object('status', v.status, 'malicious', v.malicious, 'total', v.total, 'labels', v.labels, "
        "   'last_analysis', v.last_analysis, 'permalink', v.permalink) FROM vt_verdicts v "
        "   WHERE v.tenant_key = t.tenant_key AND v.sha256 = t.observable AND t.observable_type = 'sha256') AS virustotal "
        "FROM incident_ti t JOIN iocs i ON i.id = t.ioc_id "
        "WHERE t.incident_id = :i AND t.tenant_key = :t ORDER BY t.confidence DESC, t.id"),
        {"i": incident_id, "t": current_user.tenant_key}).mappings().all()
    ti_matches = [TiMatch(**r) for r in rows]
    # Phase 7.2: recent behaviour drift for this incident's agent (advisory).
    drift = db.execute(text(
        "SELECT metric, before_value, after_value, magnitude, window_start FROM drift_events "
        "WHERE tenant_key = :t AND entity_type = 'agent' AND entity = :a ORDER BY window_start DESC LIMIT 5"),
        {"t": current_user.tenant_key, "a": row["agent_id"]}).mappings().all()
    drift_events = [DriftEvent(**d) for d in drift]
    return IncidentDetail(**row, alerts=page.alerts, alerts_next=page.next,
                          ti_matches=ti_matches, drift_events=drift_events)


def _alert_page(db: Session, settings: Settings, incident_id: int, tenant_key: str,
                after_time: datetime.datetime | None = None, after_id: int | None = None,
                limit: int = ALERT_PAGE_SIZE) -> AlertPage:
    """One keyset page of an incident's alerts, ordered by (alert_time, id). Loads at most `limit`
    membership rows from Postgres and fetches exactly those alerts' content from ClickHouse - the
    IN-list is bounded by `limit`, never the whole incident. `next` is null on the last page."""
    rows = db.execute(text(
        "SELECT node, alert_id, alert_time, id FROM incident_alerts "
        "WHERE incident_id = :i AND tenant_key = :t "
        "AND (CAST(:after_time AS timestamptz) IS NULL OR (alert_time, id) > (CAST(:after_time AS timestamptz), :after_id)) "
        "ORDER BY alert_time, id LIMIT :lim"),
        {"i": incident_id, "t": tenant_key, "after_time": after_time, "after_id": after_id, "lim": limit}).all()
    if not rows:
        return AlertPage(alerts=[], next=None)
    # Bounded IN-list: at most `limit` (<=200) pairs. node/alert_id are internal ids from our own
    # membership table, not user input (same trust as the former query). LIMIT 1 BY dedups a replay.
    pairs = ", ".join(f"('{r.node}', '{r.alert_id}')" for r in rows)
    ch_client = _get_ch_client(settings)
    try:
        result = ch_client.query(
            f"SELECT {', '.join(ALERT_COLUMNS)} FROM events "
            f"WHERE tenant_id = {{tenant_id:String}} AND (cluster_node, alert_id) IN ({pairs}) "
            f"LIMIT 1 BY cluster_node, alert_id",
            parameters={"tenant_id": tenant_key})
    finally:
        ch_client.close()
    by_key = {(d["cluster_node"], d["alert_id"]): d
              for d in (dict(zip(ALERT_COLUMNS, r)) for r in result.result_rows)}
    # Emit in the Postgres keyset order; an alert whose content aged out of ClickHouse retention is
    # skipped (not an error) rather than breaking the page.
    alerts = [IncidentAlert(**by_key[(r.node, r.alert_id)]) for r in rows if (r.node, r.alert_id) in by_key]
    nxt = AlertCursor(after_time=rows[-1].alert_time, after_id=rows[-1].id) if len(rows) == limit else None
    return AlertPage(alerts=alerts, next=nxt)


@router.get("/incidents/{incident_id}/alerts", response_model=AlertPage)
def get_incident_alerts(
    incident_id: int,
    after_time: datetime.datetime | None = None,
    after_id: int | None = None,
    limit: int = Query(ALERT_PAGE_SIZE, ge=1, le=ALERT_PAGE_SIZE),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ALL_ROLES),
):
    """Keyset page of an incident's alerts (tenant-scoped; cross-tenant -> 404). The UI pages through
    a large incident with this instead of the detail endpoint ever loading every alert."""
    exists = db.execute(
        select(incidents.c.id).where(incidents.c.id == incident_id, incidents.c.tenant_key == current_user.tenant_key)
    ).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if (after_time is None) != (after_id is None):
        raise HTTPException(status_code=422, detail="after_time and after_id must be given together")
    return _alert_page(db, settings, incident_id, current_user.tenant_key, after_time, after_id, limit)


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
