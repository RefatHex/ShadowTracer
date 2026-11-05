"""ti-sync: pull feeds into the IOC store, then generate and deploy each tenant manager
cluster's CDB lists and TI rules through the safe reload wrapper (6.1a).
Network calls happen only here, on a schedule - never on the alert hot path
(FEATURE_PLAN.md §2).

Config (env):
  TI_SYNC_INTERVAL_SECONDS   default 900
  TI_CLUSTERS                JSON: [{"tenant_key": "...", "nodes": [["master", "<container>"], ...]}]
                             first node = that cluster's master
  OTX_API_KEY                customer-supplied (lab: deploy/lab/.env); OTX is skipped without it
  OTX_FIXTURE                path to an OTX-format JSON page, used instead of the API (tests, lab VERIFY)
  TI_ENABLE_SSLBL            "1" to enable abuse.ch SSL Blacklist IPs (deprecated upstream 2025-01-03)
"""
import datetime as dt
import json
import logging
import os
import time

from sqlalchemy import create_engine, text

from . import feeds, listgen, safe_reload, store

log = logging.getLogger("ti-sync")
WARNINGLIST_REFRESH = dt.timedelta(days=1)


def database_url() -> str:
    return (f"postgresql+psycopg2://{os.environ.get('POSTGRES_USER', 'shadowtracer_app')}:"
            f"{os.environ.get('POSTGRES_PASSWORD') or os.environ.get('APP_DB_PASSWORD', '')}@"
            f"{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:{os.environ.get('POSTGRES_PORT', '5432')}/"
            f"{os.environ.get('POSTGRES_DB', 'shadowtracer')}")


def sources_from_env(env=os.environ) -> list:
    """(name, kind, enabled, snapshot, loader) - loader(cursor) -> (observations, new cursor)."""
    out = [("abusech-feodo", "feodo", True, True, lambda cur: (feeds.parse_feodo(feeds.fetch(feeds.FEODO_URL)), None)),
           ("abusech-sslbl", "sslbl", env.get("TI_ENABLE_SSLBL") == "1", True,
            lambda cur: (feeds.parse_sslbl(feeds.fetch(feeds.SSLBL_URL)), None))]
    if env.get("OTX_FIXTURE"):
        out.append(("otx", "otx", True, False,
                    lambda cur: (feeds.parse_otx_page(open(env["OTX_FIXTURE"], "rb").read())[0], None)))
    elif env.get("OTX_API_KEY"):
        out.append(("otx", "otx", True, False, lambda cur: feeds.fetch_otx(env["OTX_API_KEY"], cur)))
    return out


def sync_source(engine, name, kind, enabled, snapshot, loader) -> dict:
    with engine.begin() as conn:
        sid = store.ensure_source(conn, name, kind, enabled=enabled)
        cursor = conn.execute(text("SELECT sync_cursor FROM ti_sources WHERE id = :i"), {"i": sid}).scalar_one()
    if not enabled:
        return {"source": name, "skipped": "disabled"}
    try:
        observations, new_cursor = loader(cursor)
        with engine.begin() as conn:                                   # all-or-nothing
            counts = store.apply_observations(conn, sid, None, observations, snapshot)
            store.record_attempt(conn, sid, None, counts, new_cursor)
        return {"source": name, **counts}
    except feeds.FeedError as exc:                                     # store unchanged: last good data stays
        with engine.begin() as conn:
            store.record_attempt(conn, sid, str(exc)[:1000])
        log.warning("source %s failed, keeping the last good data: %s", name, exc)
        return {"source": name, "error": str(exc)}


def refresh_warninglists(engine, now=None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    with engine.begin() as conn:
        sid = store.ensure_source(conn, "misp-warninglists", "warninglist", trust=0)
        last = conn.execute(text("SELECT last_success_at FROM ti_sources WHERE id = :i"), {"i": sid}).scalar_one()
    if last and now - last < WARNINGLIST_REFRESH:
        return {"source": "misp-warninglists", "skipped": "fresh"}
    counts = {}
    try:
        lists = [feeds.parse_warninglist(feeds.fetch(feeds.WARNINGLIST_URL.format(name=n))) for n in feeds.WARNINGLISTS]
        with engine.begin() as conn:
            for (wl_name, entries), short in zip(lists, feeds.WARNINGLISTS):
                counts[short] = store.replace_allowlist(conn, "warninglist", short, entries, reason=wl_name)
            store.record_attempt(conn, sid, None, counts)
        return {"source": "misp-warninglists", **counts}
    except feeds.FeedError as exc:
        with engine.begin() as conn:
            store.record_attempt(conn, sid, str(exc)[:1000])
        return {"source": "misp-warninglists", "error": str(exc)}


def deploy(engine, cluster: dict) -> dict:
    nodes = [safe_reload.DockerNode(name, container) for name, container in cluster["nodes"]]
    with engine.begin() as conn:
        bundle, stats = listgen.generate(conn, cluster["tenant_key"])
    result = safe_reload.apply(nodes[0], nodes[1:], bundle)
    with engine.begin() as conn:
        store.record_versions(conn, cluster["tenant_key"], result, bundle)
    return {"tenant_key": cluster["tenant_key"], "ok": result.ok, "stats": stats,
            "nodes": {r.node: r.result for r in result.nodes}, "problems": result.problems[:5]}


def run_once(engine, env=os.environ) -> list:
    report = [refresh_warninglists(engine)]
    report += [sync_source(engine, *s) for s in sources_from_env(env)]
    report += [deploy(engine, c) for c in json.loads(env.get("TI_CLUSTERS", "[]"))]
    return report


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    engine = create_engine(database_url(), pool_pre_ping=True)
    interval = int(os.environ.get("TI_SYNC_INTERVAL_SECONDS", "900"))
    while True:
        try:
            for line in run_once(engine):
                log.info("%s", json.dumps(line, default=str))
        except Exception:  # noqa: BLE001 - one bad cycle must not stop the service
            log.exception("sync cycle failed")
        time.sleep(interval)
