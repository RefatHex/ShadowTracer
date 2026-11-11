"""CISA KEV + FIRST EPSS enrichment of CVE ids seen in alerts (Phase 6.5 A3).

ShadowTracer does not ingest Wazuh vulnerability-detector findings (they go to the Wazuh indexer,
which this stack does not run). Instead it enriches any CVE id that appears in an alert's rule
description: KEV says the CVE is being actively exploited (raise priority), EPSS gives the
exploit-probability. KEV is a small CC0 catalogue fetched in full; EPSS is fetched only for the
CVEs actually seen. Incidents whose alerts carry a CVE are tagged with cve_ids / kev_cve_ids /
max_epss. Package-level KEV watchlisting needs syscollector inventory (not in the pipeline) - backlog.
"""
import datetime as dt
import json
import logging
import re
import urllib.request

log = logging.getLogger("ti-sync.cve")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EPSS_BATCH = 100
KEV_PRIORITY_FLOOR = 13          # an actively-exploited CVE makes the incident at least this urgent

# Attribution (LICENSE_INVENTORY.md §3): KEV is CC0 (no attribution required; no CISA logo/seal);
# EPSS is FIRST.org, free, courtesy attribution "EPSS <score> - FIRST.org".
ATTRIBUTION = "CISA KEV (CC0) · FIRST EPSS"


def _get(url: str, timeout: float = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "shadowtracer-ti-sync"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_kev(body: bytes) -> list:
    obj = json.loads(body)
    out = []
    for v in obj.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").upper()
        if not CVE_RE.fullmatch(cve):
            continue
        out.append({
            "cve_id": cve, "vendor_project": v.get("vendorProject"), "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded") or None, "due_date": v.get("dueDate") or None,
            "known_ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known"})
    return out


def refresh_kev(conn, http=_get) -> int:
    rows = parse_kev(http(KEV_URL))
    for r in rows:
        conn.execute(_kev_upsert, r)
    return len(rows)


def parse_epss(body: bytes) -> dict:
    """FIRST EPSS API JSON (or CSV fallback) -> {cve: (epss, percentile, date)}."""
    out = {}
    for d in (json.loads(body).get("data") or []):
        cve = (d.get("cve") or "").upper()
        if CVE_RE.fullmatch(cve):
            out[cve] = (float(d.get("epss") or 0.0),
                        float(d["percentile"]) if d.get("percentile") else None, d.get("date"))
    return out


def fetch_epss(cves, http=_get) -> dict:
    """EPSS for a set of CVEs, in batches (the API takes a comma-separated cve list)."""
    scores, cves = {}, sorted({c.upper() for c in cves if CVE_RE.fullmatch(c or "")})
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        scores.update(parse_epss(http(f"{EPSS_API}?cve={','.join(batch)}")))
    return scores


def store_epss(conn, scores: dict) -> None:
    for cve, (epss, pct, date) in scores.items():
        conn.execute(_epss_upsert, {"cve_id": cve, "epss": epss, "percentile": pct, "scored_date": date or None})


def cve_mentions(ch, tenant_key: str, since: dt.datetime, limit: int = 20000) -> list:
    """(node, alert_id, [cves]) for alerts whose rule description carries a CVE id. Bounded."""
    if ch is None:
        return []
    # scan the whole alert (rule description, mitre refs, log text), not just the description, so
    # "any CVE id in any alert" is caught - bounded by the time window and LIMIT.
    rows = ch.query(
        "SELECT cluster_node, alert_id, arrayDistinct(extractAll(upper(raw_event), "
        "'CVE-[0-9]{4}-[0-9]{4,7}')) AS cves FROM events "
        "WHERE tenant_id = {t:String} AND time >= {since:DateTime64(3)} AND raw_event ILIKE '%CVE-%' "
        f"LIMIT {int(limit)}",
        parameters={"t": tenant_key, "since": since}).result_rows
    return [(node, aid, list(cves)) for node, aid, cves in rows if cves]


def tag_incidents(engine, ch, tenant_key: str, now: dt.datetime = None, days: int = 7, http=_get) -> dict:
    """Enrich incidents (in the window) whose alerts mention a CVE: set cve_ids, kev_cve_ids (those
    in KEV), max_epss, and floor priority for a KEV hit. Fetches EPSS for any new CVEs first."""
    from sqlalchemy import text
    now = now or dt.datetime.now(dt.timezone.utc)
    mentions = cve_mentions(ch, tenant_key, now - dt.timedelta(days=days))
    if not mentions:
        return {"incidents": 0, "cves": 0}
    # map (node, alert_id) -> incident, aggregate CVEs per incident
    per_incident, all_cves = {}, set()
    with engine.begin() as conn:
        for node, aid, cves in mentions:
            inc = conn.execute(text("SELECT incident_id FROM incident_alerts WHERE tenant_key=:t AND node=:n "
                                    "AND alert_id=:a"), {"t": tenant_key, "n": node, "a": aid}).scalar()
            if inc is None:
                continue
            s = per_incident.setdefault(inc, set())
            s.update(c.upper() for c in cves)
            all_cves.update(c.upper() for c in cves)
    if not per_incident:
        return {"incidents": 0, "cves": 0}
    # EPSS for any CVE we do not have yet
    with engine.begin() as conn:
        have = {r[0] for r in conn.execute(text("SELECT cve_id FROM epss_scores WHERE cve_id = ANY(:c)"),
                                           {"c": list(all_cves)})}
    missing = all_cves - have
    if missing:
        try:
            with engine.begin() as conn:
                store_epss(conn, fetch_epss(missing, http))
        except (OSError, ValueError) as exc:
            log.warning("EPSS fetch failed (enrichment continues without it): %s", exc)
    with engine.begin() as conn:
        kev = {r[0] for r in conn.execute(text("SELECT cve_id FROM kev_vulnerabilities WHERE cve_id = ANY(:c)"),
                                          {"c": list(all_cves)})}
        epss = {r[0]: r[1] for r in conn.execute(text("SELECT cve_id, epss FROM epss_scores WHERE cve_id = ANY(:c)"),
                                                 {"c": list(all_cves)})}
        for inc, cves in per_incident.items():
            cve_list = sorted(cves)
            kev_list = sorted(cves & kev)
            max_epss = max((epss.get(c, 0.0) for c in cves), default=None)
            # priority is a generated column that includes a KEV floor (migration c6f1a3b5d7e9), so
            # setting kev_cve_ids raises priority automatically - never written here directly.
            conn.execute(text(
                "UPDATE incidents SET cve_ids=:c, kev_cve_ids=:k, max_epss=:e, cve_enriched_at=:now WHERE id=:i"),
                {"c": cve_list, "k": kev_list, "e": max_epss, "now": now, "i": inc})
    return {"incidents": len(per_incident), "cves": len(all_cves), "kev": len(all_cves & kev)}


# SQL bound once (sqlalchemy text)
from sqlalchemy import text as _text  # noqa: E402

_kev_upsert = _text(
    "INSERT INTO kev_vulnerabilities (cve_id, vendor_project, product, vulnerability_name, date_added, "
    " due_date, known_ransomware, refreshed_at) VALUES (:cve_id, :vendor_project, :product, "
    " :vulnerability_name, :date_added, :due_date, :known_ransomware, now()) "
    "ON CONFLICT (cve_id) DO UPDATE SET vendor_project=EXCLUDED.vendor_project, product=EXCLUDED.product, "
    " vulnerability_name=EXCLUDED.vulnerability_name, date_added=EXCLUDED.date_added, due_date=EXCLUDED.due_date, "
    " known_ransomware=EXCLUDED.known_ransomware, refreshed_at=now()")
_epss_upsert = _text(
    "INSERT INTO epss_scores (cve_id, epss, percentile, scored_date, refreshed_at) "
    "VALUES (:cve_id, :epss, :percentile, :scored_date, now()) "
    "ON CONFLICT (cve_id) DO UPDATE SET epss=EXCLUDED.epss, percentile=EXCLUDED.percentile, "
    " scored_date=EXCLUDED.scored_date, refreshed_at=now()")
