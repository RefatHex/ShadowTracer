"""VirusTotal (Phase 6.3, THREAT_INTEL.md §1.8, §3.4). Runs inside ti-sync, never on the
alert hot path.

Flow: integratord on each manager runs custom-shadowtracer-virustotal for FIM alerts
550/554, which only spools the hash locally. VTWorker.step(), every few seconds:
  1. collect  - take each manager's spool; a tenant with VirusTotal off has its spool
                discarded unread (no hash from it is ever stored or sent);
  2. resolve  - each pending hash: a fresh cached verdict (Postgres vt_verdicts) answers
                it with no call; otherwise one v3 lookup if the key's per-minute/per-day
                limits and the tenant's daily budget allow it; otherwise it stays queued
                ("budget reached" in /health/detail, never an error);
  3. deliver  - a malicious verdict for a FIM alert goes back to that alert's manager as a
                `virustotal` event (Wazuh's own integration shape: rules 0490 + ShadowTracer
                TI rule 110100), becomes a tenant-private hash IOC, and is linked to the
                FIM alert's incident (incident_ti, ti_matches) like a ti-matcher hit.
Hashes only (SHA-256), never files. Keys come from env vars named per tenant (TI_VT_KEYS);
calls are logged by key fingerprint, never the key.
"""
import datetime as dt
import hashlib
import json
import logging
import re
import urllib.error
import urllib.request
from collections import Counter

from sqlalchemy import text

from . import matcher, store
from .feeds import Observation

log = logging.getLogger("ti-sync.vt")

API = "https://www.virustotal.com/api/v3/files/{}"
GUI = "https://www.virustotal.com/gui/file/{}"
# Public API: "limited to 500 requests per day and a rate of 4 requests per minute"; it
# "must not be used in commercial products or services" - customers bring their own key.
# docs.virustotal.com/reference/public-vs-premium-api, read 2026-11-06.
PUBLIC_PER_MINUTE, PUBLIC_PER_DAY = 4, 500
TTL = {"malicious": dt.timedelta(days=30), "clean": dt.timedelta(days=7), "unknown": dt.timedelta(days=7)}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
QUOTA_COOLDOWN = dt.timedelta(seconds=65)


class VTError(Exception):
    pass


class QuotaExceeded(VTError):
    pass


def key_fp(key: str) -> str:
    return "vtkey-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def _http_get(url: str, headers: dict, timeout: float = 20) -> tuple:
    req = urllib.request.Request(url, headers={"User-Agent": "shadowtracer-ti-sync", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def parse_report(sha256: str, body: bytes, now: dt.datetime) -> dict:
    a = json.loads(body)["data"]["attributes"]
    stats = a.get("last_analysis_stats") or {}
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
    names = Counter(r.get("result") for r in (a.get("last_analysis_results") or {}).values()
                    if r.get("category") == "malicious" and r.get("result"))
    suggested = (a.get("popular_threat_classification") or {}).get("suggested_threat_label")
    labels = ([suggested] if suggested else []) + [n for n, _ in names.most_common(3) if n != suggested]
    ts = lambda k: dt.datetime.fromtimestamp(a[k], dt.timezone.utc) if a.get(k) else None  # noqa: E731
    status = "malicious" if malicious > 0 else "clean"
    return {"sha256": sha256, "status": status, "malicious": malicious, "suspicious": suspicious, "total": total,
            "labels": labels, "first_submission": ts("first_submission_date"), "last_analysis": ts("last_analysis_date"),
            "permalink": GUI.format(sha256), "md5": a.get("md5"), "sha1": a.get("sha1"),
            "fetched_at": now, "expires_at": now + TTL[status]}


def lookup(sha256: str, key: str, now: dt.datetime, http=_http_get) -> tuple:
    """-> (verdict, http status). 404 = VirusTotal has never seen the file ("unknown")."""
    status, body = http(API.format(sha256), {"x-apikey": key, "accept": "application/json"})
    if status == 200:
        return parse_report(sha256, body, now), status
    if status == 404:
        return {"sha256": sha256, "status": "unknown", "malicious": 0, "suspicious": 0, "total": 0, "labels": [],
                "first_submission": None, "last_analysis": None, "permalink": GUI.format(sha256),
                "fetched_at": now, "expires_at": now + TTL["unknown"]}, status
    if status == 429:
        raise QuotaExceeded("HTTP 429 (quota exceeded)")
    raise VTError(f"HTTP {status}")                       # the key never appears in an error


def cached(conn, tenant: str, sha256: str, now: dt.datetime):
    return conn.execute(text("SELECT * FROM vt_verdicts WHERE tenant_key = :t AND sha256 = :h AND expires_at > :now"),
                        {"t": tenant, "h": sha256, "now": now}).mappings().first()


def budget(conn, tenant: str, fp: str, now: dt.datetime, daily_budget: int,
           per_minute: int = PUBLIC_PER_MINUTE, per_day: int = PUBLIC_PER_DAY) -> dict:
    """Calls already made: by the tenant today (its own budget) and with this key in the
    last minute and today (the key's limits, shared by every tenant using it)."""
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    r = conn.execute(text(
        "SELECT count(*) FILTER (WHERE tenant_key = :t AND called_at >= :day) AS tenant_today, "
        "       count(*) FILTER (WHERE key_fp = :k AND called_at >= :day) AS key_today, "
        "       count(*) FILTER (WHERE key_fp = :k AND called_at > :minute) AS key_minute "
        "FROM vt_calls WHERE called_at >= LEAST(:day, :minute)"),
        {"t": tenant, "k": fp, "day": day, "minute": now - dt.timedelta(seconds=60)}).mappings().one()
    reason = ("tenant daily budget" if r["tenant_today"] >= daily_budget else
              "key daily limit" if r["key_today"] >= per_day else
              "key per-minute limit" if r["key_minute"] >= per_minute else None)
    return {**r, "allowed": reason is None, "reason": reason}


def store_verdict(conn, tenant: str, v: dict) -> None:
    conn.execute(text(
        "INSERT INTO vt_verdicts (tenant_key, sha256, status, malicious, suspicious, total, labels, first_submission, "
        " last_analysis, permalink, fetched_at, expires_at) VALUES (:t, :sha256, :status, :malicious, :suspicious, :total, "
        " :labels, :first_submission, :last_analysis, :permalink, :fetched_at, :expires_at) "
        "ON CONFLICT (tenant_key, sha256) DO UPDATE SET status = EXCLUDED.status, malicious = EXCLUDED.malicious, "
        " suspicious = EXCLUDED.suspicious, total = EXCLUDED.total, labels = EXCLUDED.labels, "
        " first_submission = EXCLUDED.first_submission, last_analysis = EXCLUDED.last_analysis, "
        " fetched_at = EXCLUDED.fetched_at, expires_at = EXCLUDED.expires_at"), {"t": tenant, **v})


def verdict_event(v, req: dict, served_from: str) -> dict:
    """Wazuh's own virustotal integration output (integrations/virustotal.py), so rules
    87100-87106 decode it, plus ShadowTracer fields."""
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {"integration": "virustotal", "virustotal": {
        "found": 1, "malicious": 1 if v["status"] == "malicious" else 0,
        "source": {"alert_id": req["alert_id"], "file": req["path"], "md5": req["md5"], "sha1": req["sha1"]},
        "sha256": v["sha256"], "scan_date": iso(v["last_analysis"]), "positives": v["malicious"], "total": v["total"],
        "permalink": v["permalink"], "labels": list(v["labels"]), "first_submission": iso(v["first_submission"]),
        "last_analysis": iso(v["last_analysis"]), "served_from": served_from, "origin": "shadowtracer"}}


def queue_message(event: dict, req: dict) -> str:
    """The analysisd queue line, exactly as virustotal.py's send_msg builds it."""
    if not req.get("agent_id") or req["agent_id"] == "000":
        return "1:virustotal:" + json.dumps(event)
    location = f"[{req['agent_id']}] ({req['agent_name']}) {req.get('agent_ip') or 'any'}"
    return "1:" + location.replace("|", "||").replace(":", "|:") + "->virustotal:" + json.dumps(event)


def confidence(v) -> int:
    """0-100 for incident_ti/ti_matches: VirusTotal trust 0.9 x engine agreement."""
    return round(100 * 0.9 * min(1.0, 0.5 + v["malicious"] / 20))


class VTWorker:
    """clusters: TI_CLUSTERS entries {tenant_key, nodes:[[name, container], ...]};
    nodes(name, container) -> a node with spool_take/spool_delete/spool_discard/send_event;
    keys: {tenant_key: api key}. ch: optional ClickHouse client for ti_matches."""

    def __init__(self, engine, clusters, keys, node_factory, ch=None, http=_http_get,
                 per_minute=PUBLIC_PER_MINUTE, per_day=PUBLIC_PER_DAY):
        self.engine, self.keys, self.ch, self.http = engine, keys, ch, http
        self.per_minute, self.per_day = per_minute, per_day
        self.nodes = {c["tenant_key"]: [node_factory(n, ctr) for n, ctr in c["nodes"]] for c in clusters}
        self.cooldown = {}                                   # key fp -> until (after HTTP 429)
        self.stats = Counter()

    def settings(self, conn, tenant):
        r = conn.execute(text("SELECT vt_enabled, vt_daily_budget FROM ti_tenant_settings WHERE tenant_key = :t"),
                         {"t": tenant}).first()
        return (bool(r[0]), int(r[1])) if r else (False, 0)

    def collect(self) -> None:
        for tenant, nodes in self.nodes.items():
            with self.engine.begin() as conn:
                enabled, _ = self.settings(conn, tenant)
            for node in nodes:
                if not node.deployed():
                    continue
                if not enabled:
                    n = node.spool_discard()                 # unread: opt-in off means nothing leaves
                    if n:
                        self.stats["discarded_opt_in_off"] += n
                        log.info("tenant %s: VirusTotal off, discarded %d spooled hashes on %s", tenant, n, node.name)
                    continue
                taken = node.spool_take()
                with self.engine.begin() as conn:
                    for _, req in taken:
                        if not SHA256.match(str(req.get("sha256", ""))):
                            continue
                        agent = req.get("agent") or {}
                        conn.execute(text(
                            "INSERT INTO vt_requests (tenant_key, sha256, origin, node, alert_id, alert_time, rule_id, agent_id, "
                            " agent_name, agent_ip, path, md5, sha1) VALUES (:t, :h, 'fim', :node, :aid, :at, :rule, :agid, :agn, "
                            " :agip, :path, :md5, :sha1) ON CONFLICT DO NOTHING"),
                            {"t": tenant, "h": req["sha256"], "node": req.get("node") or node.name, "aid": req.get("alert_id"),
                             "at": req.get("alert_time"), "rule": req.get("rule_id"), "agid": agent.get("id"),
                             "agn": agent.get("name"), "agip": agent.get("ip"), "path": req.get("path"),
                             "md5": req.get("md5"), "sha1": req.get("sha1")})
                node.spool_delete([name for name, _ in taken])   # only after the requests are committed

    def resolve(self, now=None) -> None:
        now = now or dt.datetime.now(dt.timezone.utc)
        for tenant in self.nodes:
            with self.engine.begin() as conn:
                enabled, daily = self.settings(conn, tenant)
                pending = [r[0] for r in conn.execute(text(
                    "SELECT sha256 FROM vt_requests WHERE tenant_key = :t AND state = 'pending' "
                    "GROUP BY sha256 ORDER BY min(requested_at)"), {"t": tenant})]
            key = self.keys.get(tenant)
            for sha in pending:
                with self.engine.begin() as conn:
                    if cached(conn, tenant, sha, now):
                        self._resolved(conn, tenant, sha, "cache", now)
                        self.stats["cache_hits"] += 1
                        continue
                    if not enabled or not key:
                        continue                              # opt-in turned off since: never sent
                    fp = key_fp(key)
                    if self.cooldown.get(fp, now) > now:
                        break
                    b = budget(conn, tenant, fp, now, daily, self.per_minute, self.per_day)
                    if not b["allowed"]:
                        self.stats[f"waiting:{b['reason']}"] += 1
                        break                                 # stays queued; health shows it
                try:
                    v, status = lookup(sha, key, now, self.http)
                except QuotaExceeded:
                    self.cooldown[fp] = now + QUOTA_COOLDOWN
                    self._call(tenant, fp, sha, 429, "quota_exceeded")
                    break
                except (VTError, OSError, ValueError, KeyError) as exc:
                    self._call(tenant, fp, sha, None, f"error: {str(exc)[:200]}")
                    log.warning("VirusTotal lookup failed for tenant %s: %s", tenant, exc)
                    break
                with self.engine.begin() as conn:
                    conn.execute(text("INSERT INTO vt_calls (key_fp, tenant_key, sha256, called_at, http_status, outcome) "
                                      "VALUES (:k, :t, :h, :at, :s, :o)"),
                                 {"k": fp, "t": tenant, "h": sha, "at": now, "s": status, "o": v["status"]})
                    store_verdict(conn, tenant, v)
                    self._resolved(conn, tenant, sha, "api", now)
                self.stats["api_calls"] += 1

    def _call(self, tenant, fp, sha, status, outcome):
        with self.engine.begin() as conn:
            conn.execute(text("INSERT INTO vt_calls (key_fp, tenant_key, sha256, http_status, outcome) VALUES (:k, :t, :h, :s, :o)"),
                         {"k": fp, "t": tenant, "h": sha, "s": status, "o": outcome})

    @staticmethod
    def _resolved(conn, tenant, sha, served_from, now):
        conn.execute(text("UPDATE vt_requests SET state = 'resolved', resolved_at = :now, served_from = :f "
                          "WHERE tenant_key = :t AND sha256 = :h AND state = 'pending'"),
                     {"now": now, "f": served_from, "t": tenant, "h": sha})

    def deliver(self, now=None) -> None:
        now = now or dt.datetime.now(dt.timezone.utc)
        for tenant, nodes in self.nodes.items():
            by_name = {n.name: n for n in nodes}
            with self.engine.begin() as conn:
                rows = conn.execute(text(
                    "SELECT r.*, v.status, v.malicious AS v_malicious, v.total AS v_total, v.labels AS v_labels, "
                    " v.first_submission AS v_first, v.last_analysis AS v_last, v.permalink AS v_link "
                    "FROM vt_requests r JOIN vt_verdicts v ON v.tenant_key = r.tenant_key AND v.sha256 = r.sha256 "
                    "WHERE r.tenant_key = :t AND r.state = 'resolved' AND r.delivered_at IS NULL ORDER BY r.id"),
                    {"t": tenant}).mappings().all()
            for r in rows:
                if r["origin"] == "fim" and r["status"] == "malicious":
                    v = {"sha256": r["sha256"].strip(), "status": r["status"], "malicious": r["v_malicious"], "total": r["v_total"],
                         "labels": r["v_labels"], "first_submission": r["v_first"], "last_analysis": r["v_last"],
                         "permalink": r["v_link"]}
                    node = by_name.get(r["node"]) or nodes[0]
                    node.send_event(queue_message(verdict_event(v, r, r["served_from"]), r))
                    self._annotate(tenant, r, v, now)
                    self.stats["delivered_malicious"] += 1
                with self.engine.begin() as conn:
                    conn.execute(text("UPDATE vt_requests SET delivered_at = :now WHERE id = :i"), {"now": now, "i": r["id"]})

    def _annotate(self, tenant, r, v, now) -> None:
        """Tenant-private hash IOC (later sightings hit locally, by CDB and ti-matcher) and
        the incident link for the FIM alert, exactly like a ti-matcher hit."""
        conf = confidence(v)
        with self.engine.begin() as conn:
            sid = store.ensure_source(conn, f"virustotal:{tenant}", "virustotal", tenant_key=tenant, trust=0.9)
            obs = [Observation("sha256", v["sha256"], source_ref=v["permalink"], reference_url=v["permalink"],
                               source_info=", ".join(v["labels"][:3]), source_confidence=conf / 90, tlp="amber",
                               labels=list(v["labels"]), first_seen=v["first_submission"] or now, last_seen=now)]
            store.apply_observations(conn, sid, tenant, obs, snapshot=False, now=now)
            ioc_id = conn.execute(text("SELECT id FROM iocs WHERE tenant_key = :t AND type = 'sha256' AND value = :v"),
                                  {"t": tenant, "v": v["sha256"]}).scalar_one()
            row = {"tenant_key": tenant, "node": r["node"], "alert_id": r["alert_id"],
                   "alert_time": r["alert_time"] or now, "rule_id": r["rule_id"] or "", "field": "syscheck.sha256_after",
                   "observable_type": "sha256", "observable": v["sha256"], "ioc_id": ioc_id, "ioc_value": v["sha256"],
                   "sources": ["virustotal"], "confidence": conf}
            matcher.write_pg(conn, [row])                    # incident_ti + link + incident ti_confidence
        if self.ch is not None:
            rows = matcher.ch_rows([row], now)
            for x in rows:
                x[12] = "virustotal"                         # origin
            self.ch.insert("ti_matches", rows, column_names=matcher.CH_COLUMNS)

    def step(self) -> None:
        self.collect()
        self.resolve()
        self.deliver()
