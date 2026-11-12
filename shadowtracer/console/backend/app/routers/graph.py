"""Phase 7.6: on-demand event-relationship graph for an incident or a campaign (analyst+).

Tenant comes from the token only; a cross-tenant id returns 404. Built from the tenant's own
Postgres (incident_alerts, incident_ti, incidents.cve_ids, campaign_incidents) and ClickHouse
(events) data, off the hot path, and cached per incident/campaign version (its last_seen).
"""
import time
from collections import OrderedDict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import graph as graphlib
from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ANALYST_OR_ABOVE, CurrentUser
from .incidents import _get_ch_client

router = APIRouter(prefix="/api", tags=["graph"])

GRAPH_COLS = ("toUnixTimestamp(time) AS ts, agent_id, agent_name, rule_id, rule_level, rule_description, "
              "rule_groups, mitre_techniques, src_endpoint_ip, dst_endpoint_ip, actor_user, target_user, "
              "extra_fields['syscheck.path'] AS file, extra_fields['yara_rule'] AS yararule")
MAX_ALERTS = 5000
CAMPAIGN_INCIDENT_CAP = 25
_CACHE: "OrderedDict[tuple, dict]" = OrderedDict()
_CACHE_MAX = 128


def _cache_get(key):
    v = _CACHE.get(key)
    if v is not None:
        _CACHE.move_to_end(key)
    return v


def _cache_put(key, value):
    _CACHE[key] = value
    _CACHE.move_to_end(key)
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)


def _alerts_for(ch, tenant: str, memberships) -> list:
    if not memberships:
        return []
    pairs = ", ".join(f"('{n}', '{a}')" for n, a in memberships)
    rows = ch.query(
        f"SELECT {GRAPH_COLS} FROM events WHERE tenant_id = {{t:String}} AND (cluster_node, alert_id) IN ({pairs}) "
        f"ORDER BY time LIMIT {MAX_ALERTS}", parameters={"t": tenant}).result_rows
    out = []
    for (ts, agent_id, agent_name, rid, rlvl, rdesc, rgroups, mitre, sip, dip, au, tu, f, yara) in rows:
        out.append({"time": int(ts), "agent_id": agent_id, "agent_name": agent_name, "rule_id": rid,
                    "rule_level": rlvl, "rule_description": rdesc, "rule_groups": list(rgroups),
                    "mitre_techniques": list(mitre), "src_ip": sip or None, "dst_ip": dip or None,
                    "actor_user": au or None, "target_user": tu or None, "file": f or None,
                    "yara_rule": yara or None})
    return out


def _incident_payload(db: Session, settings: Settings, tenant: str, inc_row, memberships) -> dict:
    ti = db.execute(text("SELECT observable_type, observable, sources FROM incident_ti "
                         "WHERE incident_id = :i AND tenant_key = :t"),
                    {"i": inc_row["id"], "t": tenant}).mappings().all()
    ch = _get_ch_client(settings)
    try:
        alerts = _alerts_for(ch, tenant, memberships)
    finally:
        ch.close()
    return graphlib.build_incident_graph(alerts, [dict(m) for m in ti],
                                         inc_row["cve_ids"], inc_row["kev_cve_ids"], inc_row["agent_id"])


@router.get("/incidents/{incident_id}/graph")
def incident_graph(incident_id: int, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                   current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    inc = db.execute(text("SELECT id, agent_id, last_seen, cve_ids, kev_cve_ids FROM incidents "
                          "WHERE id = :i AND tenant_key = :t"),
                     {"i": incident_id, "t": current_user.tenant_key}).mappings().first()
    if inc is None:
        raise HTTPException(status_code=404, detail="incident not found")   # cross-tenant -> 404
    key = ("incident", incident_id, inc["last_seen"].isoformat() if inc["last_seen"] else "")
    hit = _cache_get(key)
    if hit is not None:
        return {**hit, "cached": True}
    t0 = time.monotonic()
    # cap the alerts pulled for a very large incident (bounded time window): the most recent MAX_ALERTS
    memberships = db.execute(text("SELECT node, alert_id FROM incident_alerts WHERE incident_id = :i AND tenant_key = :t "
                                  "ORDER BY alert_time DESC LIMIT :lim"),
                             {"i": incident_id, "t": current_user.tenant_key, "lim": MAX_ALERTS}).all()
    g = _incident_payload(db, settings, current_user.tenant_key, inc, memberships)
    g["summary"]["alerts_considered"] = len(memberships)
    g["response_ms"] = round((time.monotonic() - t0) * 1000, 1)
    _cache_put(key, g)
    return {**g, "cached": False}


@router.get("/campaigns/{campaign_id}/graph")
def campaign_graph(campaign_id: int, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                   current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    camp = db.execute(text("SELECT id, actor_type, actor_value, last_seen FROM campaigns "
                           "WHERE id = :c AND tenant_key = :t"),
                      {"c": campaign_id, "t": current_user.tenant_key}).mappings().first()
    if camp is None:
        raise HTTPException(status_code=404, detail="campaign not found")   # cross-tenant -> 404
    key = ("campaign", campaign_id, camp["last_seen"].isoformat() if camp["last_seen"] else "")
    hit = _cache_get(key)
    if hit is not None:
        return {**hit, "cached": True}
    t0 = time.monotonic()
    inc_ids = [r[0] for r in db.execute(text(
        "SELECT incident_id FROM campaign_incidents WHERE campaign_id = :c AND tenant_key = :t ORDER BY incident_id"),
        {"c": campaign_id, "t": current_user.tenant_key})][:CAMPAIGN_INCIDENT_CAP]
    merged = graphlib.GraphBuilder()
    per_incident = {}
    ch = _get_ch_client(settings)
    try:
        for iid in inc_ids:
            inc = db.execute(text("SELECT id, agent_id, cve_ids, kev_cve_ids FROM incidents WHERE id = :i AND tenant_key = :t"),
                             {"i": iid, "t": current_user.tenant_key}).mappings().first()
            if inc is None:
                continue
            memberships = db.execute(text("SELECT node, alert_id FROM incident_alerts WHERE incident_id = :i AND tenant_key = :t "
                                          "ORDER BY alert_time DESC LIMIT :lim"),
                                     {"i": iid, "t": current_user.tenant_key, "lim": MAX_ALERTS // 5}).all()
            alerts = _alerts_for(ch, current_user.tenant_key, memberships)
            ti = db.execute(text("SELECT observable_type, observable, sources FROM incident_ti "
                                 "WHERE incident_id = :i AND tenant_key = :t"),
                            {"i": iid, "t": current_user.tenant_key}).mappings().all()
            # a per-incident builder only to capture this incident's node set (shared-node analytics)
            solo = graphlib.GraphBuilder()
            for a in alerts:
                solo.add_alert(a); merged.add_alert(a)
            for m in ti:
                solo.add_ti_match(dict(m)); merged.add_ti_match(dict(m))
            merged.add_cves(inc["agent_id"], inc["cve_ids"], inc["kev_cve_ids"])
            per_incident[iid] = {n["id"] for n in solo.result()["nodes"]}
    finally:
        ch.close()
    result = merged.result()
    result["shared_nodes"] = graphlib.shared_nodes_across_incidents(per_incident)
    result["incident_count"] = len(per_incident)
    result["campaign_actor"] = f"{camp['actor_type']}:{camp['actor_value']}"
    result["response_ms"] = round((time.monotonic() - t0) * 1000, 1)
    _cache_put(key, result)
    return {**result, "cached": False}
