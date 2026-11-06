"""Retro-hunt (Phase 6.4, THREAT_INTEL.md §4.5): when new IOCs arrive, search each tenant's
stored events of the last TI_RETRO_DAYS (default 7) for them. Runs in ti-sync after a sync
cycle - never on the alert hot path - and is bounded per tenant: at most one run per
TI_RETRO_INTERVAL_SECONDS, MAX_IOCS new IOCs and MAX_EVENTS candidate events per run, and
a ClickHouse time limit.

Matching is ti-matcher's own (`matcher.match` over the same observables) against a set of
only the new IOCs, so a retro hit is exactly what the live matcher would have found. The
ClickHouse query narrows candidates by exact value (source/destination IP, any field value
equal to a hash, domain or URL); parent-domain and CIDR matches are live-only for now.
Matches go to incident_ti (origin retro) and ClickHouse ti_matches (retro = true), linked
to their incidents; an alert already matched to that IOC is left as it was.
"""
import datetime as dt
import json
import logging
from types import SimpleNamespace

from sqlalchemy import text

from . import listgen, matcher

log = logging.getLogger("ti-sync.retro")
MAX_IOCS = 5000
MAX_EVENTS = 20000
OVERLAP = dt.timedelta(hours=1)          # IOCs written by a long sync transaction commit late
CH_SETTINGS = {"max_execution_time": 60, "max_result_rows": MAX_EVENTS, "result_overflow_mode": "break"}
HASHES = ("md5", "sha1", "sha256")


def _new_iocs(conn, tenant_key, since, upto, now):
    """-> (IocSet of IOCs created in (since, upto] visible to the tenant, new cursor). Over
    MAX_IOCS: the oldest MAX_IOCS now, the cursor stops at the last one, the rest next run."""
    found = conn.execute(text(
        "SELECT id, created FROM iocs WHERE created > :a AND created <= :b AND NOT revoked "
        "AND (tenant_key IS NULL OR tenant_key = :t) ORDER BY created, id LIMIT :n"),
        {"a": since, "b": upto, "t": tenant_key, "n": MAX_IOCS + 1}).all()
    cursor = upto if len(found) <= MAX_IOCS else found[MAX_IOCS - 1][1]
    found = found[:MAX_IOCS]
    if not found:
        return matcher.IocSet([]), cursor
    rows, allow = listgen.load(conn, tenant_key, now, scope="all", ids=[r[0] for r in found])
    return matcher.IocSet.from_rows(rows, allow, now), cursor


def candidates(ch, tenant_key: str, iocs: matcher.IocSet, days: int, now: dt.datetime) -> list:
    ips = [v for (t, v) in iocs.exact if t in ("ipv4", "ipv6")]
    values = [v for (t, v) in iocs.exact if t not in ("ipv4", "ipv6")]
    if not ips and not values:
        return []
    res = ch.query(
        "SELECT cluster_node, alert_id, toString(time), rule_id, rule_groups, extra_fields FROM events "
        "WHERE tenant_id = {t:String} AND time >= {since:DateTime64(3)} AND ("
        " has({ips:Array(String)}, src_endpoint_ip) OR has({ips:Array(String)}, dst_endpoint_ip)"
        " OR hasAny(mapValues(extra_fields), {vals:Array(String)})) "
        f"ORDER BY time LIMIT {MAX_EVENTS}",
        parameters={"t": tenant_key, "since": now - dt.timedelta(days=days), "ips": ips, "vals": values},
        settings=CH_SETTINGS)
    return [SimpleNamespace(tenant_id=tenant_key, cluster_node=node, alert_id=aid,
                            time=t.replace(" ", "T") + "+00:00", rule_id=rule, rule_groups=list(groups),
                            extra_fields=dict(fields))
            for node, aid, t, rule, groups, fields in res.result_rows]


def run(engine, ch, tenant_key: str, now: dt.datetime = None, days: int = 7,
        min_interval: dt.timedelta = dt.timedelta(minutes=15)) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    with engine.begin() as conn:
        state = conn.execute(text("SELECT cursor, last_run_at FROM ti_retro_state WHERE tenant_key = :t"),
                             {"t": tenant_key}).first()
        if state is None:                      # first run: only IOCs from now on are hunted
            conn.execute(text("INSERT INTO ti_retro_state (tenant_key, cursor) VALUES (:t, :now)"),
                         {"t": tenant_key, "now": now})
            return {"tenant_key": tenant_key, "retro": "initialised"}
    cursor, last_run = state
    if last_run and now - last_run < min_interval:
        return {"tenant_key": tenant_key, "retro": "skipped (interval)"}
    with engine.begin() as conn:
        iocs, upto = _new_iocs(conn, tenant_key, cursor - OVERLAP, now, now)
    counts = {"new_iocs": iocs.size, "events_checked": 0, "matches": 0}
    new = []
    if iocs.size:
        events = candidates(ch, tenant_key, iocs, days, now)
        counts["events_checked"] = len(events)
        rows = [dict(r, origin="retro") for ev in events for r in matcher.match(ev, iocs, now)]
        with engine.begin() as conn:
            new = matcher.write_pg(conn, rows)
        if new:
            ch.insert("ti_matches", matcher.ch_rows(new, now), column_names=matcher.CH_COLUMNS)
        counts["matches"] = len(new)
    with engine.begin() as conn:
        conn.execute(text("UPDATE ti_retro_state SET cursor = :c, last_run_at = :now, last_counts = CAST(:k AS jsonb) "
                          "WHERE tenant_key = :t"), {"c": upto, "now": now, "k": json.dumps(counts), "t": tenant_key})
    if new:
        log.info("retro-hunt tenant %s: %s", tenant_key, counts)
    return {"tenant_key": tenant_key, "retro": counts}
