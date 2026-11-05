"""ti-matcher: annotate alerts that already fired with threat-intel matches
(THREAT_INTEL.md §3.1). A side consumer, never on the hot path:

- Own consumer group on every tenant's alerts topic; the tenant is the topic's, never
  the alert's. If it lags or stops, ingestion and correlation carry on; it resumes from
  its committed offsets.
- One in-memory IOC set per tenant (global + that tenant's private, minus allowlists,
  scored exactly like the CDB lists: listgen.evaluate), including the low band and the
  shapes CDB cannot hold (any CIDR, parent domains, URLs). Reloaded when
  ti_store_version moves (polled every TI_MATCHER_POLL_SECONDS) and at least every
  TI_MATCHER_MAX_AGE_SECONDS, because confidence decays with time.
- Writes ClickHouse ti_matches and Postgres incident_ti; links each match to the
  alert's incident once the correlator has created it, and raises incidents.ti_confidence
  (incidents.priority is generated from it). Never touches the alert.
- At-least-once: offsets are committed only after both writes; both are idempotent on
  (alert identity, IOC id), so a replay or redelivery adds nothing.
- No network calls except Kafka, Postgres and ClickHouse.
"""
import datetime as dt
import ipaddress
import json
import logging
import time
from typing import NamedTuple
from urllib.parse import urlsplit

from sqlalchemy import text

from . import listgen
from .normalise import Rejected, normalise

log = logging.getLogger("ti-matcher")

TI_RULE_GROUP = "shadowtracer_ti"       # CDB TI alerts: analysisd already matched them
URL_FIELDS = ("url",)                    # last component of a flattened field name
DOMAIN_FIELDS = ("domain", "hostname", "queryname")
HASH_FIELDS = {"syscheck.sha256_after": "sha256", "syscheck.sha1_after": "sha1", "syscheck.md5_after": "md5"}
CH_COLUMNS = ["tenant_id", "cluster_node", "alert_id", "ioc_id", "alert_time", "rule_id", "field",
              "observable_type", "observable", "ioc_value", "sources", "confidence", "origin", "matched_at"]
LINK_WINDOW = "1 day"                    # alerts that never join an incident stop being retried


class Hit(NamedTuple):
    ioc_id: int
    type: str
    value: str
    confidence: int
    sources: tuple
    expires_at: dt.datetime


class IocSet:
    """O(1) lookups: exact values in one dict; CIDRs in one dict per prefix length."""

    def __init__(self, hits, version=None):
        self.version, self.loaded_at = version, dt.datetime.now(dt.timezone.utc)
        self.exact, self.nets, self.by_type = {}, {4: {}, 6: {}}, {}
        for h in hits:
            self.by_type[h.type] = self.by_type.get(h.type, 0) + 1
            if h.type in ("cidr4", "cidr6"):
                net = ipaddress.ip_network(h.value)
                self.nets[net.version].setdefault(net.prefixlen, {}).setdefault(net, []).append(h)
            else:
                self.exact.setdefault((h.type, h.value), []).append(h)
        self.size = sum(self.by_type.values())

    @classmethod
    def from_rows(cls, rows, allow, now, version=None):
        return cls([Hit(ioc_id, typ, value, c, tuple(sorted({s["source"] for s in sightings})),
                        listgen.expires_at(typ, sightings))
                    for ioc_id, typ, value, c, _, sightings in listgen.evaluate(rows, allow, now)], version)

    def lookup(self, typ: str, value: str, now: dt.datetime) -> list:
        hits = list(self.exact.get((typ, value), ()))
        if typ in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(value)
            for plen, nets in self.nets[ip.version].items():
                hits += nets.get(ipaddress.ip_network((ip, plen), strict=False), ())
        elif typ == "domain":
            labels = value.split(".")
            for i in range(1, len(labels) - 1):            # parents, never the bare TLD
                hits += self.exact.get(("domain", ".".join(labels[i:])), ())
        return [h for h in hits if h.expires_at > now]


def _add(out: dict, field: str, typ: str, raw):
    """Normalise one observable into out {(type, value): field}; returns the value or None."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        typ, value = normalise(typ, raw, "tenant")
    except Rejected:
        return None
    if typ in ("cidr4", "cidr6"):
        return None
    out.setdefault((typ, value), field)
    return value


def observables(event) -> list:
    """[(field, type, value)] from a NormalizedEvent: source/destination IPs, URLs (and
    their host), domain fields, FIM hashes. Each (type, value) once per alert."""
    out = {}
    fields = event.extra_fields
    _add(out, "data.srcip", "ipv4", fields.get("data.srcip"))      # "ipv4" also accepts IPv6
    _add(out, "data.dstip", "ipv4", fields.get("data.dstip"))
    for name, raw in fields.items():
        last = name.rsplit(".", 1)[-1].lower()
        if name in HASH_FIELDS:
            _add(out, name, HASH_FIELDS[name], raw)
        elif last.endswith(URL_FIELDS):
            url = _add(out, name, "url", raw)
            if url:
                host = urlsplit(url).hostname
                try:
                    ipaddress.ip_address(host)
                    _add(out, name + ".host", "ipv4", host)
                except ValueError:
                    _add(out, name + ".host", "domain", host)
        elif last.endswith(DOMAIN_FIELDS):
            _add(out, name, "domain", raw)
    return [(field, typ, value) for (typ, value), field in out.items()]


def match(event, iocs: IocSet, now: dt.datetime) -> list:
    """Match rows for one alert ([] for the ShadowTracer TI rules' own alerts)."""
    if TI_RULE_GROUP in event.rule_groups:
        return []
    rows = {}
    for field, typ, value in observables(event):
        for h in iocs.lookup(typ, value, now):
            rows.setdefault(h.ioc_id, {
                "tenant_key": event.tenant_id, "node": event.cluster_node, "alert_id": event.alert_id,
                "alert_time": dt.datetime.fromisoformat(event.time), "rule_id": event.rule_id, "field": field,
                "observable_type": typ, "observable": value, "ioc_id": h.ioc_id, "ioc_value": h.value,
                "sources": list(h.sources), "confidence": h.confidence})
    return list(rows.values())


def store_version(conn) -> int:
    return conn.execute(text("SELECT version FROM ti_store_version")).scalar_one()


def load_set(conn, tenant_key: str, instance: str) -> IocSet:
    now = dt.datetime.now(dt.timezone.utc)
    version = store_version(conn)                       # read first: a change during the load triggers another
    rows, allow = listgen.load(conn, tenant_key, now)
    iocs = IocSet.from_rows(rows, allow, now, version)
    conn.execute(text(
        "INSERT INTO ti_matcher_state (instance, tenant_key, store_version, iocs, by_type, loaded_at) "
        "VALUES (:i, :t, :v, :n, CAST(:b AS jsonb), :at) ON CONFLICT (instance, tenant_key) DO UPDATE SET "
        "store_version = EXCLUDED.store_version, iocs = EXCLUDED.iocs, by_type = EXCLUDED.by_type, "
        "loaded_at = EXCLUDED.loaded_at"),
        {"i": instance, "t": tenant_key, "v": version, "n": iocs.size, "b": json.dumps(iocs.by_type), "at": now})
    return iocs


def write_pg(conn, rows: list) -> None:
    if rows:
        conn.execute(text(
            "INSERT INTO incident_ti (tenant_key, node, alert_id, alert_time, rule_id, ioc_id, field, observable_type, "
            "observable, ioc_value, sources, confidence) VALUES (:tenant_key, :node, :alert_id, :alert_time, :rule_id, "
            ":ioc_id, :field, :observable_type, :observable, :ioc_value, :sources, :confidence) "
            "ON CONFLICT (tenant_key, node, alert_id, ioc_id) DO NOTHING"), rows)
    link(conn)


def link(conn) -> int:
    """Attach unlinked matches to the incident the correlator put their alert in, and
    raise that incident's ti_confidence. Returns how many matches were linked."""
    return conn.execute(text(f"""
        WITH linked AS (
          UPDATE incident_ti t SET incident_id = ia.incident_id FROM incident_alerts ia
          WHERE t.incident_id IS NULL AND t.created_at > now() - interval '{LINK_WINDOW}'
            AND ia.tenant_key = t.tenant_key AND ia.node = t.node AND ia.alert_id = t.alert_id
          RETURNING t.incident_id, t.confidence),
        raised AS (
          UPDATE incidents i SET ti_confidence = m.c
          FROM (SELECT incident_id, max(confidence) AS c FROM linked GROUP BY incident_id) m
          WHERE i.id = m.incident_id AND (i.ti_confidence IS NULL OR i.ti_confidence < m.c))
        SELECT count(*) FROM linked""")).scalar_one()


def ch_rows(rows: list, now: dt.datetime) -> list:
    return [[r["tenant_key"], r["node"], r["alert_id"], r["ioc_id"], r["alert_time"], r["rule_id"], r["field"],
             r["observable_type"], r["observable"], r["ioc_value"], r["sources"], r["confidence"], "matcher", now]
            for r in rows]


class Matcher:
    """The consume loop. consumer: a confluent_kafka Consumer already subscribed;
    tenant_of(topic) -> tenant key or None; known(tenant) -> bool."""

    def __init__(self, consumer, engine, ch, tenant_of, known, instance, poll_s=60, max_age_s=3600,
                 batch=500, normalize=None, stop=None):
        from shadowtracer_ingest.normalizer import normalize_alert
        self.consumer, self.engine, self.ch, self.instance = consumer, engine, ch, instance
        self.tenant_of, self.known, self.normalize = tenant_of, known, normalize or normalize_alert
        self.poll_s, self.max_age_s, self.batch, self.stop = poll_s, max_age_s, batch, stop
        self.sets, self.version, self.checked = {}, None, 0.0
        self.stats = {"alerts": 0, "matches": 0, "skipped": 0, "since": time.monotonic()}

    def clear_state(self) -> None:
        """A fresh process has loaded nothing: drop the previous incarnation's rows so
        /health/detail never reports a set this process does not hold."""
        with self.engine.begin() as conn:
            conn.execute(text("DELETE FROM ti_matcher_state WHERE instance = :i"), {"i": self.instance})

    def iocs(self, tenant: str) -> IocSet:
        if tenant not in self.sets:
            with self.engine.begin() as conn:
                self.sets[tenant] = load_set(conn, tenant, self.instance)
            log.info("loaded tenant %s: %d IOCs %s (store version %s)", tenant, self.sets[tenant].size,
                     self.sets[tenant].by_type, self.sets[tenant].version)
        return self.sets[tenant]

    def maybe_reload(self) -> None:
        if time.monotonic() - self.checked < self.poll_s:
            return
        self.checked = time.monotonic()
        with self.engine.begin() as conn:
            version = store_version(conn)
            link(conn)                                          # matches whose incident appeared since
        now = dt.datetime.now(dt.timezone.utc)
        for tenant, s in list(self.sets.items()):
            if s.version != version or (now - s.loaded_at).total_seconds() >= self.max_age_s:
                del self.sets[tenant]
                self.iocs(tenant)

    def process(self, msgs) -> list:
        """-> match rows for a batch (pure apart from loading IOC sets)."""
        now = dt.datetime.now(dt.timezone.utc)
        rows = []
        for msg in msgs:
            if msg.error():
                continue
            tenant = self.tenant_of(msg.topic())
            if not tenant or not self.known(tenant):
                self.stats["skipped"] += 1                     # the correlator dead-letters these
                continue
            try:
                event = self.normalize(msg.value().decode("utf-8", errors="replace"), tenant)
            except Exception:  # noqa: BLE001 - bad data is dead-lettered by writer/correlator, not here
                self.stats["skipped"] += 1
                continue
            self.stats["alerts"] += 1
            rows += match(event, self.iocs(tenant), now)
        return rows

    def write(self, rows: list) -> None:
        if rows:
            self.ch.insert("ti_matches", ch_rows(rows, dt.datetime.now(dt.timezone.utc)), column_names=CH_COLUMNS)
        with self.engine.begin() as conn:
            write_pg(conn, rows)
        self.stats["matches"] += len(rows)

    def step(self) -> int:
        from confluent_kafka import TopicPartition
        self.maybe_reload()
        msgs = self.consumer.consume(num_messages=self.batch, timeout=1.0)
        if not msgs:
            return 0
        attempt = 0
        while True:                    # transient failure: retry in place, never commit, never skip
            try:
                self.write(self.process(msgs))
                break
            except Exception as exc:  # noqa: BLE001
                attempt += 1
                log.warning("batch of %d failed (attempt %d), retrying: %s", len(msgs), attempt, exc)
                if self.stop is not None and self.stop.wait(min(2 ** attempt, 30)):
                    return 0           # shutting down: uncommitted, redelivered on restart
        offsets = {}
        for m in msgs:
            if not m.error():
                offsets[(m.topic(), m.partition())] = max(offsets.get((m.topic(), m.partition()), -1), m.offset())
        if offsets:
            self.consumer.commit(offsets=[TopicPartition(t, p, o + 1) for (t, p), o in offsets.items()],
                                 asynchronous=False)
        return len(msgs)

    def log_stats(self, every_s=30) -> None:
        elapsed = time.monotonic() - self.stats["since"]
        if elapsed >= every_s:
            log.info("alerts=%d matches=%d skipped=%d rate=%.0f/s", self.stats["alerts"], self.stats["matches"],
                     self.stats["skipped"], self.stats["alerts"] / elapsed)
            self.stats = {"alerts": 0, "matches": 0, "skipped": 0, "since": time.monotonic()}
