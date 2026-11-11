"""On-demand IP reputation lookups for analysts (Phase 6.5 C).

AbuseIPDB and GreyNoise are NOT automatic background workers - an analyst clicks an IP in the
incident view and the backend, which holds the KEK, opens that tenant's own key, calls the
source once, caches the verdict and audits the call. Same per-tenant key / opt-in / budget /
cache / audit as the other paid sources. Pure HTTP clients (http injectable for tests); the
router applies the key, budget and cache around them.
"""
import json
import urllib.error
import urllib.parse
import urllib.request

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_URL = "https://api.greynoise.io/v3/community/"


class IPSourceError(Exception):
    pass


class IPSourceAuthError(IPSourceError):
    pass


class IPSourceQuotaExceeded(IPSourceError):
    pass


def _http_get(url: str, headers: dict, timeout: float = 15) -> tuple:
    req = urllib.request.Request(url, headers={"User-Agent": "shadowtracer-console", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _check(status: int, source: str) -> None:
    if status == 429:
        raise IPSourceQuotaExceeded(f"{source} rate limit (HTTP 429)")
    if status in (401, 403):
        raise IPSourceAuthError(f"{source} auth failed (HTTP {status})")
    if status != 200:
        raise IPSourceError(f"{source} HTTP {status}")


def abuseipdb_lookup(ip: str, key: str, http=_http_get) -> dict:
    """-> {source, indicator, status, data}. status from abuseConfidenceScore: >=75 malicious,
    >=25 suspicious, else clean."""
    url = f"{ABUSEIPDB_URL}?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    status, body = http(url, {"Key": key, "Accept": "application/json"})
    _check(status, "AbuseIPDB")
    d = (json.loads(body) or {}).get("data") or {}
    score = int(d.get("abuseConfidenceScore") or 0)
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
    return {"source": "abuseipdb", "indicator": ip, "status": verdict, "data": {
        "abuse_confidence_score": score, "total_reports": d.get("totalReports"),
        "country_code": d.get("countryCode"), "isp": d.get("isp"), "domain": d.get("domain"),
        "usage_type": d.get("usageType"), "is_tor": d.get("isTor"),
        "last_reported_at": d.get("lastReportedAt"),
        "permalink": f"https://www.abuseipdb.com/check/{ip}"}}


def greynoise_lookup(ip: str, key: str, http=_http_get) -> dict:
    """-> {source, indicator, status, data}. GreyNoise community: classification malicious/benign,
    riot = known benign service. 404 means 'not observed' (unknown), not an error."""
    status, body = http(f"{GREYNOISE_URL}{urllib.parse.quote(ip)}", {"key": key, "Accept": "application/json"})
    if status == 404:
        return {"source": "greynoise", "indicator": ip, "status": "unknown",
                "data": {"noise": False, "riot": False, "message": "IP not observed"}}
    _check(status, "GreyNoise")
    d = json.loads(body) or {}
    cls = d.get("classification")
    verdict = "malicious" if cls == "malicious" else "clean" if cls in ("benign",) else "unknown"
    if d.get("riot") and verdict == "unknown":
        verdict = "clean"            # RIOT = common benign business service
    return {"source": "greynoise", "indicator": ip, "status": verdict, "data": {
        "noise": d.get("noise"), "riot": d.get("riot"), "classification": cls,
        "name": d.get("name"), "last_seen": d.get("last_seen"),
        "permalink": d.get("link") or f"https://viz.greynoise.io/ip/{ip}"}}


LOOKUPS = {"abuseipdb": abuseipdb_lookup, "greynoise": greynoise_lookup}
