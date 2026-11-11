"""ti-sync: pull feeds into the IOC store, then generate and deploy each tenant manager
cluster's CDB lists and TI rules through the safe reload wrapper (6.1a).
Network calls happen only here, on a schedule - never on the alert hot path
(FEATURE_PLAN.md §2).

Config (env):
  TI_SYNC_INTERVAL_SECONDS   default 900
  TI_CLUSTERS                JSON: [{"tenant_key": "...", "nodes": [["master", "<container>"], ...]}]
                             first node = that cluster's master
  OTX_API_KEY                customer-supplied (lab: deploy/lab/.env); OTX is skipped without it
  OTX_FIXTURE                path to an OTX-format JSON page, used instead of the API (tests, lab VERIFY);
                             stored as source "otx-fixture", never mixed with real OTX data
  OTX_INITIAL_DAYS           first OTX sync (no cursor yet) starts this many days back (default 30):
                             older pulses' IOCs are mostly past their TTL, and the whole sync is
                             one transaction held in memory
  TI_FEED_<NAME>             "1"/"0" turns a feed of FEEDS on/off, overriding its product default
                             (name upper-cased, "-" -> "_": TI_FEED_CIRCL_OSINT=1). Defaults follow
                             each feed's licence: on only where commercial use is clearly allowed
                             (THREAT_INTEL.md §6.2 feed table).
  TI_MISP_SERVERS            JSON: [{"tenant_key", "name", "url", "key_env", "verify_tls"}] - a tenant's
                             own MISP server; the API key is read from the env var named by key_env
                             (lab: deploy/lab/.env), never stored in the database
"""
import datetime as dt
import json
import logging
import os
import time
from dataclasses import dataclass

from sqlalchemy import create_engine, text

from . import feeds, listgen, safe_reload, store, tor_exit

log = logging.getLogger("ti-sync")
WARNINGLIST_REFRESH = dt.timedelta(days=1)
MISP_FEED_INITIAL_DAYS = 365          # longest hard TTL (hashes): older events would only expire
H, D = dt.timedelta(hours=1), dt.timedelta(days=1)


@dataclass
class Feed:
    """One global feed. kind is the store's source kind (trust default, health staleness).
    loader(cursor) -> (observations, new cursor); misp_url instead of a loader for MISP feeds."""
    name: str
    kind: str
    default_on: bool
    licence: str
    loader: object = None
    snapshot: bool = True
    trust: float = None
    min_interval: dt.timedelta = dt.timedelta(0)
    min_prefix: dict = None
    misp_url: str = None


def _list(url, typ, label, min_entries, confidence=None, sep=None, column=0):
    return lambda cur: (feeds.parse_list(feeds.fetch(url, timeout=120), typ, label, min_entries, confidence, sep, column), None)


FEEDS = [
    Feed("abusech-feodo", "feodo", True, "CC0 (abuse.ch terms)",
         lambda cur: (feeds.parse_feodo(feeds.fetch(feeds.FEODO_URL)), None)),
    Feed("abusech-sslbl", "sslbl", False, "CC0; IP list deprecated upstream 2025-01-03",
         lambda cur: (feeds.parse_sslbl(feeds.fetch(feeds.SSLBL_URL)), None)),
    # "The DROP list is free for any use ... regardless of size or business type";
    # downloads at most once a day; keep the copyright/terms with the data.
    Feed("spamhaus-drop-v4", "spamhaus_drop", True, "Spamhaus DROP terms: free for any use, max 1 download/day",
         lambda cur: (feeds.parse_spamhaus_drop(feeds.fetch(feeds.SPAMHAUS_DROP_URLS["ipv4"])), None),
         trust=0.9, min_interval=D, min_prefix={4: 8, 6: 16}),
    Feed("spamhaus-drop-v6", "spamhaus_drop", True, "Spamhaus DROP terms: free for any use, max 1 download/day",
         lambda cur: (feeds.parse_spamhaus_drop(feeds.fetch(feeds.SPAMHAUS_DROP_URLS["ipv6"])), None),
         trust=0.9, min_interval=D, min_prefix={4: 8, 6: 16}),
    # "may be used by any user for any purpose, including commercial purposes"
    Feed("certpl-domains", "certpl", True, "CERT Polska warning list: any purpose incl. commercial",
         _list("https://hole.cert.pl/domains/v2/domains.txt", "domain", "certpl-warning-list", 1000, 0.9),
         trust=0.8, min_interval=H),
    Feed("circl-osint", "misp_feed", False, "none published (events TLP:CLEAR/WHITE); customer-enabled",
         snapshot=False, trust=0.8, min_interval=H, misp_url="https://www.circl.lu/doc/misp/feed-osint"),
    Feed("botvrij-osint", "misp_feed", False, "botvrij.eu FAQ: free, but no resale incl. as part of a package",
         snapshot=False, trust=0.6, min_interval=H, misp_url="https://www.botvrij.eu/data/feed-osint"),
    Feed("blocklist-de", "ip_list", False, "no licence grant; terms silent on commercial use",
         _list("https://lists.blocklist.de/lists/all.txt", "ipv4", "blocklist-de", 1000), trust=0.6, min_interval=H),
    Feed("cins-army", "ip_list", False, "'use in any way you see fit', no licence; ask CINS for commercial use",
         _list("https://cinsscore.com/list/ci-badguys.txt", "ipv4", "cins-army", 1000), trust=0.6, min_interval=H),
    Feed("et-compromised", "ip_list", False, "GPL-2.0 per an unofficial ET forum reply; unclear",
         _list("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ipv4", "et-compromised", 100),
         trust=0.6, min_interval=H),
    Feed("dataplane-sshpwauth", "ip_list", False, "dataplane.org: All Rights Reserved",
         _list("https://dataplane.org/sshpwauth.txt", "ipv4", "dataplane-sshpwauth", 100, sep="|", column=2), trust=0.6, min_interval=H),
]
MIN_INTERVAL = {"otx": dt.timedelta(minutes=15)}       # per kind, on top of each feed's own


def database_url() -> str:
    return (f"postgresql+psycopg2://{os.environ.get('POSTGRES_USER', 'shadowtracer_app')}:"
            f"{os.environ.get('POSTGRES_PASSWORD') or os.environ.get('APP_DB_PASSWORD', '')}@"
            f"{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:{os.environ.get('POSTGRES_PORT', '5432')}/"
            f"{os.environ.get('POSTGRES_DB', 'shadowtracer')}")


def _enabled(feed: Feed, env) -> bool:
    v = env.get("TI_FEED_" + feed.name.upper().replace("-", "_"))
    if feed.name == "abusech-sslbl" and env.get("TI_ENABLE_SSLBL") == "1":
        return True
    return feed.default_on if v is None else v == "1"


def sources_from_env(env=os.environ) -> list:
    out = [Feed(f.name, f.kind, _enabled(f, env), f.licence, f.loader, f.snapshot, f.trust, f.min_interval,
                f.min_prefix, f.misp_url) for f in FEEDS]
    if env.get("OTX_FIXTURE"):
        out.append(Feed("otx-fixture", "otx", True, "lab fixture",
                        lambda cur: (feeds.parse_otx_page(open(env["OTX_FIXTURE"], "rb").read())[0], None), snapshot=False))
    elif env.get("OTX_API_KEY"):
        initial = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=int(env.get("OTX_INITIAL_DAYS", "30")))).isoformat()
        out.append(Feed("otx", "otx", True, "customer's OTX account",
                        lambda cur: feeds.fetch_otx(env["OTX_API_KEY"], cur or initial), snapshot=False,
                        min_interval=MIN_INTERVAL["otx"]))
    return out


def _start(engine, feed: Feed, tenant_key=None):
    """-> (source id, cursor) or (None, skip reason)."""
    with engine.begin() as conn:
        sid = store.ensure_source(conn, feed.name, feed.kind, tenant_key=tenant_key, trust=feed.trust, enabled=feed.default_on)
        cursor, last_attempt = conn.execute(text("SELECT sync_cursor, last_attempt_at FROM ti_sources WHERE id = :i"),
                                            {"i": sid}).one()
    if not feed.default_on:
        return None, "disabled"
    if last_attempt and dt.datetime.now(dt.timezone.utc) - last_attempt < feed.min_interval:
        return None, "minimum interval"
    return sid, cursor


def _failed(engine, sid, name, exc) -> dict:
    with engine.begin() as conn:                                       # store unchanged: last good data stays
        store.record_attempt(conn, sid, str(exc)[:1000])
    log.warning("source %s failed, keeping the last good data: %s", name, exc)
    return {"source": name, "error": str(exc)}


def sync_source(engine, feed: Feed, tenant_key: str = None) -> dict:
    if feed.misp_url:
        return sync_misp_feed(engine, feed)
    sid, cursor = _start(engine, feed, tenant_key)
    if sid is None:
        return {"source": feed.name, "skipped": cursor}
    try:
        observations, new_cursor = feed.loader(cursor)
        with engine.begin() as conn:                                   # all-or-nothing
            counts = store.apply_observations(conn, sid, tenant_key, observations, feed.snapshot, min_prefix=feed.min_prefix)
            store.record_attempt(conn, sid, None, counts, new_cursor)
        return {"source": feed.name, **counts}
    except feeds.FeedError as exc:
        return _failed(engine, sid, feed.name, exc)


def sync_misp_feed(engine, feed: Feed, fetch=None) -> dict:
    """MISP feed: manifest, then every event changed since the cursor (first run: the last
    MISP_FEED_INITIAL_DAYS), oldest first, ONE TRANSACTION PER EVENT so memory stays one
    event. The cursor (event timestamp) advances after each committed event, so a failure
    resumes from the first event not yet imported."""
    fetch = fetch or feeds.fetch
    sid, cursor = _start(engine, feed)
    if sid is None:
        return {"source": feed.name, "skipped": cursor}
    since = int(cursor) if cursor else int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=MISP_FEED_INITIAL_DAYS)).timestamp())
    total = {"events": 0, "received": 0, "accepted": 0, "rejected": {}, "by_type": {}}
    try:
        manifest = feeds.parse_misp_manifest(fetch(f"{feed.misp_url}/manifest.json", timeout=120))
        for uuid_, ts in sorted(((u, t) for u, t in manifest.items() if t > since), key=lambda x: x[1]):
            url = f"{feed.misp_url}/{uuid_}.json"
            obs = feeds.parse_misp_event(fetch(url, timeout=120), url)
            with engine.begin() as conn:
                c = store.apply_observations(conn, sid, None, obs, snapshot=False, min_prefix=feed.min_prefix)
                conn.execute(text("UPDATE ti_sources SET sync_cursor = :c WHERE id = :i"), {"c": str(ts), "i": sid})
            total["events"] += 1
            for k in ("received", "accepted"):
                total[k] += c[k]
            for k in ("rejected", "by_type"):
                for t, n in c[k].items():
                    total[k][t] = total[k].get(t, 0) + n
        with engine.begin() as conn:
            store.record_attempt(conn, sid, None, total)
        return {"source": feed.name, **total}
    except feeds.FeedError as exc:
        return {**_failed(engine, sid, feed.name, exc), "events_imported": total["events"]}


def sync_misp_servers(engine, env=os.environ) -> list:
    """Each tenant's own MISP server (TI_MISP_SERVERS): tenant-private intel only."""
    from . import misp_server
    out = []
    for srv in json.loads(env.get("TI_MISP_SERVERS", "[]")):
        key = env.get(srv["key_env"], "")
        feed = Feed(f"misp-server:{srv['tenant_key']}:{srv['name']}", "misp_server", bool(key), "tenant's own MISP",
                    snapshot=False, trust=srv.get("trust", 0.8), min_interval=MIN_INTERVAL["otx"],
                    loader=lambda cur, srv=srv, key=key: misp_server.fetch(
                        srv["url"], key, int(cur) if cur else None, srv.get("verify_tls", True)))
        out.append(sync_source(engine, feed, tenant_key=srv["tenant_key"]))
    return out


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
    nodes = [nodes[0]] + [n for n in nodes[1:] if n.deployed()]      # master always; absent workers skipped
    with engine.begin() as conn:
        bundle, stats = listgen.generate(conn, cluster["tenant_key"])
    result = safe_reload.apply(nodes[0], nodes[1:], bundle)
    with engine.begin() as conn:
        store.record_versions(conn, cluster["tenant_key"], result, bundle)
    return {"tenant_key": cluster["tenant_key"], "ok": result.ok, "stats": stats,
            "nodes": {r.node: r.result for r in result.nodes}, "problems": result.problems[:5]}


def record_key_status(engine, env=os.environ) -> None:
    """6.4: whether each key is configured (yes/no, never the value) for the console."""
    clusters = json.loads(env.get("TI_CLUSTERS", "[]"))
    vt_keys = json.loads(env.get("TI_VT_KEYS", "{}"))
    rows = [("otx", None, bool(env.get("OTX_API_KEY")))]
    rows += [("virustotal", c["tenant_key"], bool(env.get(vt_keys.get(c["tenant_key"], ""), ""))) for c in clusters]
    rows += [(f"misp-server:{s['name']}", s["tenant_key"], bool(env.get(s["key_env"], "")))
             for s in json.loads(env.get("TI_MISP_SERVERS", "[]"))]
    with engine.begin() as conn:
        for name, tenant, ok in rows:
            conn.execute(text("INSERT INTO ti_key_status (name, tenant_key, configured, updated_at) VALUES (:n, :t, :c, now()) "
                              "ON CONFLICT (name, tenant_key) DO UPDATE SET configured = EXCLUDED.configured, updated_at = now()"),
                         {"n": name, "t": tenant, "c": ok})


def run_retro(engine, env=os.environ) -> list:
    if not env.get("CLICKHOUSE_HOST"):
        return []
    from . import retro
    ch = clickhouse_from_env(env)
    days = int(env.get("TI_RETRO_DAYS", "7"))
    interval = dt.timedelta(seconds=int(env.get("TI_RETRO_INTERVAL_SECONDS", "900")))
    out = []
    for c in json.loads(env.get("TI_CLUSTERS", "[]")):
        try:
            out.append(retro.run(engine, ch, c["tenant_key"], days=days, min_interval=interval))
        except Exception as exc:  # noqa: BLE001 - one tenant's retro-hunt never stops the others or the sync
            log.exception("retro-hunt failed for tenant %s", c["tenant_key"])
            out.append({"tenant_key": c["tenant_key"], "retro_error": str(exc)[:300]})
    return out


TOR_REFRESH = dt.timedelta(hours=1)


def refresh_tor_exits(engine, env=os.environ, now=None) -> dict:
    """Phase 6.5 A4: keep tor_exit_nodes current (refetch when stale) and tag recent incidents.
    Context only - never an alert. Default on; disable with TI_TOR_EXIT=0."""
    if env.get("TI_TOR_EXIT", "1") == "0":
        return {"source": "tor-exit-list", "skipped": "disabled"}
    now = now or dt.datetime.now(dt.timezone.utc)
    with engine.connect() as conn:
        last = conn.execute(text("SELECT max(last_seen) FROM tor_exit_nodes")).scalar()
    counts, err = {}, None
    if not (last and now - last < TOR_REFRESH):
        try:
            ips = tor_exit.parse(feeds.fetch(tor_exit.URL, timeout=60))     # HTTP outside any txn
            if len(ips) < 50:
                raise feeds.FeedError(f"tor exit list implausibly small ({len(ips)})")   # whole-feed rejection
        except (feeds.FeedError, OSError) as exc:
            err = str(exc)[:500]
            ips = None
        if ips is not None:
            with engine.begin() as conn:
                counts = tor_exit.refresh(conn, ips, now=now)
    with engine.begin() as conn:
        tagged = tor_exit.tag_incidents(conn, now=now)
    out = {"source": "tor-exit-list", "tagged": tagged, **counts}
    if err:
        out["error"] = err
    return out


def run_once(engine, env=os.environ) -> list:
    report = [refresh_warninglists(engine), refresh_tor_exits(engine, env)]
    report += [sync_source(engine, f) for f in sources_from_env(env)]
    report += sync_misp_servers(engine, env)
    report += [deploy(engine, c) for c in json.loads(env.get("TI_CLUSTERS", "[]"))]
    record_key_status(engine, env)
    report += run_retro(engine, env)
    return report


def clickhouse_from_env(env=os.environ):
    if not env.get("CLICKHOUSE_HOST"):
        return None
    import clickhouse_connect
    return clickhouse_connect.get_client(host=env["CLICKHOUSE_HOST"], port=int(env.get("CLICKHOUSE_PORT", "8123")),
                                         username=env.get("CLICKHOUSE_USER", "default"),
                                         password=env.get("CLICKHOUSE_PASSWORD", ""),
                                         database=env.get("CLICKHOUSE_DATABASE", "shadowtracer"))


def db_vt_key_loader(engine, kek):
    """6.5 B: a callable (tenant) -> the tenant's VirusTotal key, envelope-sealed in
    tenant_source_keys and decrypted with the deployment KEK. Read per cycle so a rotation or
    removal in the console takes effect without restarting the worker. A blob that fails to open
    is logged and treated as no key (the tenant simply isn't resolved) - never a crash."""
    from . import keyvault

    def loader(tenant):
        with engine.begin() as conn:
            blob = conn.execute(text(
                "SELECT sealed_key FROM tenant_source_keys "
                "WHERE tenant_key = :t AND source = 'virustotal' AND sealed_key IS NOT NULL"),
                {"t": tenant}).scalar()
        if not blob:
            return None
        try:
            return keyvault.open_sealed(kek, tenant, "virustotal", blob)
        except keyvault.KeyVaultError:
            log.warning("could not open the VirusTotal key for tenant %s (KEK mismatch?)", tenant)
            return None
    return loader


def vt_worker_from_env(engine, env=os.environ):
    """VirusTotal worker. Keys come from the console (tenant_source_keys, envelope-sealed) when
    KEY_ENCRYPTION_KEY is set - the preferred path (6.5 B). TI_VT_KEYS (an env var per tenant) is
    the legacy fallback, used only for tenants without a DB key, and is being retired. Opt-in is
    ti_tenant_settings.vt_enabled (console, admin-only, audited); VT_PER_MINUTE / VT_PER_DAY are
    the key's limits (default: the public API's 4 and 500)."""
    from . import keyvault, vt
    keys = {t: env.get(var, "") for t, var in json.loads(env.get("TI_VT_KEYS", "{}")).items()}
    kek_raw = env.get("KEY_ENCRYPTION_KEY")
    key_loader = db_vt_key_loader(engine, keyvault.load_kek(kek_raw)) if kek_raw else None
    return vt.VTWorker(engine, json.loads(env.get("TI_CLUSTERS", "[]")), {t: k for t, k in keys.items() if k},
                       safe_reload.DockerNode, ch=clickhouse_from_env(env), per_minute=int(env.get("VT_PER_MINUTE", vt.PUBLIC_PER_MINUTE)),
                       per_day=int(env.get("VT_PER_DAY", vt.PUBLIC_PER_DAY)), key_loader=key_loader)


def _vt_loop(engine, interval: float) -> None:
    worker = None
    while True:
        try:
            worker = worker or vt_worker_from_env(engine)
            worker.step()
        except Exception:  # noqa: BLE001 - VirusTotal trouble never stops feed syncs
            log.exception("VirusTotal worker step failed")
        time.sleep(interval)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    engine = create_engine(database_url(), pool_pre_ping=True)
    import threading
    threading.Thread(target=_vt_loop, args=(engine, float(os.environ.get("TI_VT_INTERVAL_SECONDS", "10"))),
                     daemon=True, name="vt-worker").start()
    interval = int(os.environ.get("TI_SYNC_INTERVAL_SECONDS", "900"))
    while True:
        try:
            for line in run_once(engine):
                log.info("%s", json.dumps(line, default=str))
        except Exception:  # noqa: BLE001 - one bad cycle must not stop the service
            log.exception("sync cycle failed")
        time.sleep(interval)
