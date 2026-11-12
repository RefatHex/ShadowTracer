"""Phase 7.8 demo: the Live view data - a big-screen pipeline dashboard for the TEST tenant.

One polled endpoint returns the pipeline stage counters (agent events -> alerts -> Kafka -> stored
-> incidents), live tenant counts, a recent-alert ticker, recent/growing incidents, and the latest
threat-intel / YARA / VirusTotal hits. Plus a demo-settings endpoint for the fast-close knob. Every
query is scoped to the caller's tenant (from the token); the upstream stage counters come from the
tenant's own shipper metrics (LIVE_SHIPPER_METRICS_URL, lab/demo only - best-effort, null if unset
or unreachable). All log text is returned as plain strings, rendered as text in the UI.
"""
import datetime
import json
import os
import urllib.request

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ADMIN_ONLY, ALL_ROLES, CurrentUser
from .incidents import _get_ch_client

router = APIRouter(prefix="/api/live", tags=["live"])

RECENT_ALERTS = 15
RECENT_INCIDENTS = 10
RECENT_HITS = 6


def _scrape(url: str) -> dict:
    """Best-effort JSON scrape of a service's /metrics (stdlib counters). Never raises."""
    try:
        with urllib.request.urlopen(url, timeout=1.5) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


class DemoSettings(BaseModel):
    fast_close_seconds: int | None


@router.get("/demo-settings", response_model=DemoSettings)
def get_demo_settings(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    v = db.execute(text("SELECT demo_fast_close_seconds FROM tenant_alert_settings WHERE tenant_key = :t"),
                   {"t": current_user.tenant_key}).scalar()
    return DemoSettings(fast_close_seconds=v)


@router.put("/demo-settings", response_model=DemoSettings)
def put_demo_settings(body: DemoSettings, db: Session = Depends(get_db),
                      current_user: CurrentUser = Depends(ADMIN_ONLY)):
    secs = body.fast_close_seconds
    if secs is not None and not (10 <= secs <= 3600):
        raise HTTPException(status_code=422, detail="fast_close_seconds must be between 10 and 3600, or null to disable")
    # upsert the tenant's settings row, touching only the demo column
    db.execute(text(
        "INSERT INTO tenant_alert_settings (tenant_key, demo_fast_close_seconds) VALUES (:t, :s) "
        "ON CONFLICT (tenant_key) DO UPDATE SET demo_fast_close_seconds = :s, updated_at = now()"),
        {"t": current_user.tenant_key, "s": secs})
    db.commit()
    return DemoSettings(fast_close_seconds=secs)


@router.get("/overview")
def overview(db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
             current_user: CurrentUser = Depends(ALL_ROLES)):
    tenant = current_user.tenant_key
    now = datetime.datetime.now(datetime.timezone.utc)
    minute_ago = now - datetime.timedelta(seconds=60)

    # --- tenant-scoped data from the stores (authoritative) ---
    ch = _get_ch_client(settings)
    try:
        events_total = ch.query("SELECT count() FROM events WHERE tenant_id = {t:String}",
                                parameters={"t": tenant}).result_rows[0][0]
        events_last_min = ch.query(
            "SELECT count() FROM events WHERE tenant_id = {t:String} AND time >= {s:DateTime64(3)}",
            parameters={"t": tenant, "s": minute_ago}).result_rows[0][0]
        recent_alerts = [
            {"time": int(ts.timestamp()), "agent_name": an or ai, "rule_id": rid, "rule_level": lvl,
             "rule_description": rd, "message": (msg or "")[:300]}
            for ts, ai, an, rid, lvl, rd, msg in ch.query(
                "SELECT time, agent_id, agent_name, rule_id, rule_level, rule_description, message "
                "FROM events WHERE tenant_id = {t:String} ORDER BY time DESC LIMIT {n:UInt32}",
                parameters={"t": tenant, "n": RECENT_ALERTS}).result_rows]
        # TI / YARA / VT hits: recent high-signal enriched alerts (TI rule groups, YARA matches)
        hit_rows = ch.query(
            "SELECT time, agent_name, rule_id, rule_description, rule_groups, extra_fields['yara_rule'] AS yara "
            "FROM events WHERE tenant_id = {t:String} AND (hasAny(rule_groups, ['ti_high','ti_medium','virustotal']) "
            "OR rule_id IN ('110200','110201','110012','110011','87105') OR extra_fields['yara_rule'] != '') "
            "ORDER BY time DESC LIMIT {n:UInt32}",
            parameters={"t": tenant, "n": RECENT_HITS}).result_rows
        hits = []
        for ts, an, rid, rd, groups, yara in hit_rows:
            kind = ("YARA" if (yara or rid in ("110200", "110201")) else
                    "VirusTotal" if "virustotal" in groups else "Threat intel")
            hits.append({"time": int(ts.timestamp()), "agent_name": an, "kind": kind,
                         "label": yara or rd, "rule_id": rid})
    finally:
        ch.close()

    inc = db.execute(text(
        "SELECT count(*) FILTER (WHERE state='open') AS open, count(*) AS total, "
        "count(*) FILTER (WHERE first_seen >= :m) AS last_min FROM incidents WHERE tenant_key = :t"),
        {"t": tenant, "m": minute_ago}).mappings().first()
    recent_incidents = [dict(r) for r in db.execute(text(
        "SELECT id, agent_id, alert_count, max_level, state, priority, last_seen "
        "FROM incidents WHERE tenant_key = :t ORDER BY last_seen DESC LIMIT :n"),
        {"t": tenant, "n": RECENT_INCIDENTS}).mappings()]
    for r in recent_incidents:
        r["last_seen"] = r["last_seen"].isoformat() if r["last_seen"] else None

    demo_secs = db.execute(text("SELECT demo_fast_close_seconds FROM tenant_alert_settings WHERE tenant_key = :t"),
                           {"t": tenant}).scalar()

    # --- upstream stage counters from the tenant's shipper (best-effort, lab/demo) ---
    ship = _scrape(os.environ["LIVE_SHIPPER_METRICS_URL"]) if os.environ.get("LIVE_SHIPPER_METRICS_URL") else {}
    stages = [
        {"name": "Agent events", "value": ship.get("lines_read")},
        {"name": "Alerts → Kafka", "value": ship.get("lines_sent")},
        {"name": "Stored", "value": events_total},
        {"name": "Incidents", "value": inc["total"]},
    ]

    return {
        "tenant": tenant,
        "stages": stages,
        "events_total": events_total,
        "events_last_min": events_last_min,
        "incidents_open": inc["open"],
        "incidents_total": inc["total"],
        "incidents_last_min": inc["last_min"],
        "recent_alerts": recent_alerts,
        "recent_incidents": recent_incidents,
        "hits": hits,
        "demo": {"fast_close_seconds": demo_secs},
        "as_of": int(now.timestamp()),
    }
