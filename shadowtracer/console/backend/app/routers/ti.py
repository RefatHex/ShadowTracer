"""Phase 6.3: threat-intel settings and on-demand VirusTotal lookups (THREAT_INTEL.md §3.4).

The backend never calls VirusTotal and never holds a key: a lookup is answered from the
tenant's verdict cache or queued for ti-sync's VirusTotal worker, which applies the same
cache, API limits and daily budget as the automatic FIM path. Hashes only (SHA-256).
"""
import datetime
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..deps import get_db
from .. import health as health_checks
from ..rbac import ADMIN_ONLY, ALL_ROLES, ANALYST_OR_ABOVE, CurrentUser

router = APIRouter(prefix="/api/ti", tags=["threat-intel"])
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TiSettings(BaseModel):
    vt_enabled: bool = False
    vt_daily_budget: int = Field(default=500, ge=0, le=1_000_000)
    disabled_sources: list[str] = []          # global feeds this tenant does not want matched (6.4)


class LookupRequest(BaseModel):
    sha256: str


class Verdict(BaseModel):
    sha256: str
    status: str                     # malicious | clean | unknown
    malicious: int
    suspicious: int
    total: int
    labels: list[str]
    first_submission: datetime.datetime | None
    last_analysis: datetime.datetime | None
    permalink: str
    fetched_at: datetime.datetime
    expires_at: datetime.datetime


def _settings(db: Session, tenant_key: str) -> TiSettings:
    r = db.execute(text("SELECT vt_enabled, vt_daily_budget, disabled_sources FROM ti_tenant_settings WHERE tenant_key = :t"),
                   {"t": tenant_key}).mappings().first()
    return TiSettings(**r) if r else TiSettings()


def _verdict(db: Session, tenant_key: str, sha256: str):
    r = db.execute(text("SELECT * FROM vt_verdicts WHERE tenant_key = :t AND sha256 = :h AND expires_at > now()"),
                   {"t": tenant_key, "h": sha256}).mappings().first()
    return Verdict(**{k: r[k] for k in Verdict.model_fields}) if r else None


def _queue_state(db: Session, tenant_key: str, settings: TiSettings) -> str:
    used = db.execute(text("SELECT count(*) FROM vt_calls WHERE tenant_key = :t AND called_at >= date_trunc('day', now())"),
                      {"t": tenant_key}).scalar_one()
    return "budget_reached" if used >= settings.vt_daily_budget else "queued"


def _sha256(value: str) -> str:
    h = value.strip().lower()
    if not SHA256.match(h):
        raise HTTPException(status_code=422, detail="sha256 must be 64 hex characters")
    return h


@router.get("/settings", response_model=TiSettings)
def get_settings(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    return _settings(db, current_user.tenant_key)


@router.put("/settings", response_model=TiSettings)
def put_settings(body: TiSettings, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ADMIN_ONLY)):
    """VirusTotal is opt-in per tenant (default off): with it off no hash is ever sent.
    disabled_sources: global feeds whose IOCs this tenant's lists and matcher leave out."""
    known = {r[0] for r in db.execute(text("SELECT name FROM ti_sources WHERE tenant_key IS NULL"))}
    unknown = sorted(set(body.disabled_sources) - known)
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown global source(s): {', '.join(unknown)}")
    disabled = sorted(set(body.disabled_sources))
    db.execute(text(
        "INSERT INTO ti_tenant_settings (tenant_key, vt_enabled, vt_daily_budget, disabled_sources, updated_at, updated_by) "
        "VALUES (:t, :e, :b, :d, now(), :u) ON CONFLICT (tenant_key) DO UPDATE SET vt_enabled = EXCLUDED.vt_enabled, "
        "vt_daily_budget = EXCLUDED.vt_daily_budget, disabled_sources = EXCLUDED.disabled_sources, updated_at = now(), "
        "updated_by = EXCLUDED.updated_by"),
        {"t": current_user.tenant_key, "e": body.vt_enabled, "b": body.vt_daily_budget, "d": disabled,
         "u": str(current_user.user_id)})
    # the store version tells ti-matcher to reload; ti-sync's next cycle regenerates the lists
    db.execute(text("UPDATE ti_store_version SET version = version + 1, changed_at = now()"))
    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id, action="ti_settings_changed",
                 target=f"vt_enabled={body.vt_enabled},vt_daily_budget={body.vt_daily_budget},"
                        f"disabled_sources={'|'.join(disabled)}", outcome="success")
    return _settings(db, current_user.tenant_key)


@router.post("/virustotal/lookups")
def lookup(body: LookupRequest, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    """200 with the cached verdict, or 202 queued / budget_reached (the worker answers it
    when the budget allows; poll GET /api/ti/virustotal/{sha256}). Audited either way."""
    sha256 = _sha256(body.sha256)
    settings = _settings(db, current_user.tenant_key)
    audit = lambda outcome: append_entry(  # noqa: E731
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id, action="virustotal_lookup",
        target=sha256, outcome=outcome)
    # A verdict already in this tenant's cache sends nothing anywhere: it is shown even with
    # VirusTotal off. Only a NEW lookup needs the opt-in.
    v = _verdict(db, current_user.tenant_key, sha256)
    if v:
        audit("cached")
        return {"status": "cached", "verdict": v.model_dump(mode="json")}
    if not settings.vt_enabled:
        audit("refused:disabled")
        raise HTTPException(status_code=409, detail="VirusTotal is not enabled for this tenant")
    db.execute(text(
        "INSERT INTO vt_requests (tenant_key, sha256, origin, requested_by) SELECT :t, :h, 'api', :u "
        "WHERE NOT EXISTS (SELECT 1 FROM vt_requests WHERE tenant_key = :t AND sha256 = :h AND state = 'pending')"),
        {"t": current_user.tenant_key, "h": sha256, "u": str(current_user.user_id)})
    state = _queue_state(db, current_user.tenant_key, settings)
    audit(state)                                         # commits the request with the audit entry
    return JSONResponse(status_code=202, content={"status": state, "sha256": sha256})


@router.get("/virustotal/{sha256}")
def get_lookup(sha256: str, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    sha256 = _sha256(sha256)
    v = _verdict(db, current_user.tenant_key, sha256)
    if v:
        return {"status": "cached", "verdict": v.model_dump(mode="json")}
    pending = db.execute(text("SELECT 1 FROM vt_requests WHERE tenant_key = :t AND sha256 = :h AND state = 'pending'"),
                         {"t": current_user.tenant_key, "h": sha256}).first()
    if pending:
        return {"status": _queue_state(db, current_user.tenant_key, _settings(db, current_user.tenant_key)), "sha256": sha256}
    raise HTTPException(status_code=404, detail="no verdict and no pending lookup for this hash")


# --- 6.4: false positives, IOC browser, overview -------------------------------------

ALLOW_TYPE = {"ipv4": "ipv4", "ipv6": "ipv6", "domain": "domain", "url": "url", "md5": "md5", "sha1": "sha1",
              "sha256": "sha256"}
# Must equal shadowtracer_intel.listgen.HARD_TTL_DAYS (tests/test_ti_console.py checks it).
HARD_TTL_DAYS = {"ipv4": 30, "ipv6": 30, "cidr4": 30, "cidr6": 30, "url": 30, "domain": 90, "md5": 365, "sha1": 365, "sha256": 365}
TTL_SQL = "CASE i.type " + " ".join(f"WHEN '{t}' THEN {d}" for t, d in HARD_TTL_DAYS.items()) + " END"


class FalsePositiveRequest(BaseModel):
    incident_ti_id: int
    reason: str = Field(min_length=3, max_length=500)


@router.post("/false-positives")
def mark_false_positive(body: FalsePositiveRequest, db: Session = Depends(get_db),
                        current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    """The matched observable joins THIS tenant's allowlist (kind fp_marking): its lists and
    matcher stop matching it, no other tenant is affected. The label is kept for the ML phase."""
    m = db.execute(text("SELECT id, ioc_id, observable_type, observable, sources FROM incident_ti WHERE id = :i AND tenant_key = :t"),
                   {"i": body.incident_ti_id, "t": current_user.tenant_key}).mappings().first()
    if m is None:
        raise HTTPException(status_code=404, detail="TI match not found")
    db.execute(text(
        "INSERT INTO ti_allowlist (tenant_key, type, value, kind, reason, origin_ref, created_by) "
        "VALUES (:t, :ty, :v, 'fp_marking', :r, :o, :u) ON CONFLICT DO NOTHING"),
        {"t": current_user.tenant_key, "ty": ALLOW_TYPE.get(m["observable_type"], m["observable_type"]), "v": m["observable"],
         "r": body.reason, "o": f"incident_ti:{m['id']}", "u": str(current_user.user_id)})
    db.execute(text(
        "INSERT INTO ti_feedback (tenant_key, incident_ti_id, ioc_id, observable_type, observable, sources, label, reason, created_by) "
        "VALUES (:t, :i, :ioc, :ty, :v, :s, 'false_positive', :r, :u)"),
        {"t": current_user.tenant_key, "i": m["id"], "ioc": m["ioc_id"], "ty": m["observable_type"], "v": m["observable"],
         "s": list(m["sources"]), "r": body.reason, "u": str(current_user.user_id)})
    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id, action="ti_false_positive",
                 target=f"{m['observable_type']}:{m['observable']}", outcome="success")
    return {"status": "allowlisted", "observable_type": m["observable_type"], "observable": m["observable"]}


@router.get("/iocs")
def browse_iocs(q: str | None = None, type: str | None = None, source: str | None = None,
                scope: str = "all", min_confidence: int = 0, expiry: str = "live",
                limit: int = 100, offset: int = 0,
                db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    """Global IOCs and this tenant's private ones - never another tenant's. TLP: global
    intel is never AMBER/RED (rejected at import); the filter below is the backstop.
    expiry: live | expired | all (by the hard TTL from the newest sighting)."""
    if scope not in ("all", "global", "tenant") or expiry not in ("live", "expired", "all"):
        raise HTTPException(status_code=422, detail="scope: all|global|tenant; expiry: live|expired|all")
    limit = max(1, min(limit, 500))
    where = ["(i.tenant_key IS NULL OR i.tenant_key = :t)",
             "NOT (i.tenant_key IS NULL AND i.tlp IN ('amber', 'amber+strict', 'red'))", "i.confidence >= :mc"]
    if scope == "global":
        where.append("i.tenant_key IS NULL")
    elif scope == "tenant":
        where.append("i.tenant_key = :t")
    if type:
        where.append("i.type = :ty")
    if q:
        where.append("i.value ILIKE :q")
    if source:
        where.append("EXISTS (SELECT 1 FROM ioc_sightings s JOIN ti_sources src ON src.id = s.source_id "
                     "WHERE s.ioc_id = i.id AND src.name = :src AND s.revoked_at IS NULL)")
    if expiry != "all":
        where.append(f"(i.last_seen + make_interval(days => {TTL_SQL})) {'>' if expiry == 'live' else '<='} now()")
    params = {"t": current_user.tenant_key, "mc": min_confidence, "ty": type, "q": f"%{q}%" if q else None, "src": source,
              "lim": limit, "off": offset}
    total = db.execute(text(f"SELECT count(*) FROM iocs i WHERE {' AND '.join(where)}"), params).scalar_one()
    rows = db.execute(text(
        "SELECT i.id, i.type, i.value, CASE WHEN i.tenant_key IS NULL THEN 'global' ELSE 'tenant' END AS scope, i.tlp, "
        " i.confidence, i.labels, i.mitre, i.valid_from AS first_seen, i.last_seen, i.revoked, "
        f" i.last_seen + make_interval(days => {TTL_SQL}) AS expires_at, "
        " ARRAY(SELECT src.name FROM ioc_sightings s JOIN ti_sources src ON src.id = s.source_id "
        "       WHERE s.ioc_id = i.id AND s.revoked_at IS NULL ORDER BY src.name) AS sources "
        f"FROM iocs i WHERE {' AND '.join(where)} ORDER BY i.confidence DESC, i.last_seen DESC, i.id LIMIT :lim OFFSET :off"),
        params).mappings().all()
    return {"total": total, "iocs": [dict(r) for r in rows]}


@router.get("/overview")
def overview(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    """The TI settings page: feeds (global and this tenant's), per-tenant on/off, last sync,
    staleness, IOC counts, hits and false-positive rate in the last 30 days; VirusTotal
    settings and usage; which keys are configured (yes/no - the values never leave ti-sync)."""
    t = current_user.tenant_key
    settings = _settings(db, t)
    stale = {s["name"]: s for s in health_checks.ti_sources(db)["sources"]}
    rows = db.execute(text(
        "SELECT src.name, src.kind, src.tenant_key IS NOT NULL AS private, src.enabled, src.trust, src.last_success_at, "
        " src.last_error, "
        " (SELECT count(*) FROM incident_ti it WHERE it.tenant_key = :t "
        "   AND (src.name = ANY(it.sources) OR (src.kind = 'virustotal' AND 'virustotal' = ANY(it.sources))) "
        "   AND it.created_at > now() - interval '30 days') AS hits_30d, "
        " (SELECT count(*) FROM ti_feedback f WHERE f.tenant_key = :t "
        "   AND (src.name = ANY(f.sources) OR (src.kind = 'virustotal' AND 'virustotal' = ANY(f.sources))) "
        "   AND f.created_at > now() - interval '30 days') AS false_positives_30d "
        "FROM ti_sources src WHERE src.tenant_key IS NULL OR src.tenant_key = :t ORDER BY src.tenant_key NULLS FIRST, src.name"),
        {"t": t}).mappings().all()
    sources = []
    for r in rows:
        st = stale.get(r["name"], {})
        # a global source holds only global IOCs, a tenant source only that tenant's (store.py)
        sources.append({**dict(r), "iocs": st.get("live_iocs", 0), "disabled_for_tenant": r["name"] in settings.disabled_sources,
                        "stale": bool(st.get("stale")), "age_seconds": st.get("age_seconds"),
                        "fp_rate": (r["false_positives_30d"] / r["hits_30d"]) if r["hits_30d"] else None})
    keys = {name: configured for name, configured in db.execute(text(
        "SELECT name, configured FROM ti_key_status WHERE tenant_key IS NULL OR tenant_key = :t"), {"t": t})}
    vt_usage = health_checks.virustotal(db)["tenants"].get(t, {})
    retro = db.execute(text("SELECT cursor, last_run_at, last_counts FROM ti_retro_state WHERE tenant_key = :t"), {"t": t}).mappings().first()
    return {"settings": settings.model_dump(), "sources": sources, "keys": keys, "virustotal": vt_usage,
            "retro": dict(retro) if retro else None}
