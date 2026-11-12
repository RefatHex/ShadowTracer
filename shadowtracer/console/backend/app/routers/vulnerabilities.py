"""Phase 7.7: per-host / per-tenant vulnerability view over ClickHouse vulnerability_states
(landed by the indexer shim, shadowtracer_ingest/vulnshim.py), enriched with CISA KEV and FIRST
EPSS from Postgres (the same kev_vulnerabilities / epss_scores tables the incident enrichment uses).

Tenant comes from the token only (never a parameter); every query is scoped to it. Hosts and CVEs
are sorted KEV-first (actively exploited) then by EPSS - a KEV on a host raises the host's priority.
Read-only, any authenticated role.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ALL_ROLES, CurrentUser
from .incidents import _get_ch_client

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


class HostVuln(BaseModel):
    agent_id: str
    agent_name: str
    total: int
    kev_count: int
    max_epss: float | None
    max_cvss: float
    severities: dict          # {"Critical": n, "High": n, ...}
    priority: str             # critical | high | medium | low  (KEV -> critical)


class CveRow(BaseModel):
    cve_id: str
    package_name: str
    package_version: str
    severity: str
    cvss_score: float
    kev: bool
    kev_ransomware: bool
    epss: float | None
    epss_percentile: float | None
    first_seen: str
    last_seen: str


def _enrich(db: Session, cve_ids: list[str]) -> tuple[dict, dict]:
    """Returns (kev, epss) lookups for the given CVE ids from Postgres. Empty dicts for an empty
    input. KEV/EPSS are tenant-independent reference data."""
    if not cve_ids:
        return {}, {}
    kev = {r["cve_id"]: r for r in db.execute(text(
        "SELECT cve_id, vulnerability_name, known_ransomware FROM kev_vulnerabilities WHERE cve_id = ANY(:ids)"),
        {"ids": cve_ids}).mappings()}
    epss = {r["cve_id"]: r for r in db.execute(text(
        "SELECT cve_id, epss, percentile FROM epss_scores WHERE cve_id = ANY(:ids)"),
        {"ids": cve_ids}).mappings()}
    return kev, epss


def _live_rows(settings: Settings, tenant: str, agent_id: str | None):
    ch = _get_ch_client(settings)
    try:
        where = "tenant_id = {t:String} AND is_deleted = 0"
        params = {"t": tenant}
        if agent_id is not None:
            where += " AND agent_id = {a:String}"
            params["a"] = agent_id
        return ch.query(
            "SELECT agent_id, agent_name, package_name, package_version, cve_id, severity, cvss_score, "
            f"first_seen, last_seen FROM vulnerability_states FINAL WHERE {where}",
            parameters=params).result_rows
    finally:
        ch.close()


def _priority(kev_count: int, max_cvss: float) -> str:
    if kev_count > 0:
        return "critical"            # KEV on the host raises its priority
    if max_cvss >= 9.0:
        return "critical"
    if max_cvss >= 7.0:
        return "high"
    if max_cvss >= 4.0:
        return "medium"
    return "low"


@router.get("", response_model=list[HostVuln])
def list_hosts(db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
               current_user: CurrentUser = Depends(ALL_ROLES)):
    rows = _live_rows(settings, current_user.tenant_key, None)
    kev, epss = _enrich(db, list({r[4] for r in rows}))
    hosts: dict = {}
    for agent_id, agent_name, _pkg, _ver, cve, severity, cvss, _fs, _ls in rows:
        h = hosts.setdefault(agent_id, {"agent_name": agent_name, "total": 0, "kev": 0,
                                        "max_epss": None, "max_cvss": 0.0, "sev": {}})
        h["total"] += 1
        h["sev"][severity] = h["sev"].get(severity, 0) + 1
        h["max_cvss"] = max(h["max_cvss"], float(cvss))
        if cve in kev:
            h["kev"] += 1
        e = epss.get(cve)
        if e is not None:
            h["max_epss"] = e["epss"] if h["max_epss"] is None else max(h["max_epss"], e["epss"])
    out = [HostVuln(agent_id=aid, agent_name=h["agent_name"], total=h["total"], kev_count=h["kev"],
                    max_epss=h["max_epss"], max_cvss=round(h["max_cvss"], 1), severities=h["sev"],
                    priority=_priority(h["kev"], h["max_cvss"])) for aid, h in hosts.items()]
    # KEV-first, then EPSS, then CVSS - the host triage order
    out.sort(key=lambda x: (x.kev_count > 0, x.max_epss or 0, x.max_cvss), reverse=True)
    return out


@router.get("/hosts/{agent_id}", response_model=list[CveRow])
def host_cves(agent_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
              current_user: CurrentUser = Depends(ALL_ROLES)):
    rows = _live_rows(settings, current_user.tenant_key, agent_id)
    if not rows:
        # a host with no live vulns is a valid empty list; only a cross-tenant / unknown id with no
        # rows returns the same - no CVE data to leak either way.
        return []
    kev, epss = _enrich(db, list({r[4] for r in rows}))
    out = []
    for _aid, _name, pkg, ver, cve, severity, cvss, first_seen, last_seen in rows:
        k, e = kev.get(cve), epss.get(cve)
        out.append(CveRow(
            cve_id=cve, package_name=pkg, package_version=ver, severity=severity,
            cvss_score=round(float(cvss), 1), kev=k is not None,
            kev_ransomware=bool(k["known_ransomware"]) if k else False,
            epss=e["epss"] if e else None, epss_percentile=e["percentile"] if e else None,
            first_seen=str(first_seen), last_seen=str(last_seen)))
    out.sort(key=lambda x: (x.kev, x.epss or 0, x.cvss_score), reverse=True)
    return out
