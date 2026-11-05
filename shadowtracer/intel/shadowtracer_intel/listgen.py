"""Generate one tenant manager cluster's CDB lists from the IOC store.
THREAT_INTEL.md §4.3 (lists), §4.8 (allowlists), §4.10 (confidence, decay, bands),
§4.11 (one entry per observable), §4.13 (TLP).

Lists hold global IOCs plus that tenant's private ones, minus allowlists, banded by the
combined confidence C = 100 * (1 - prod(1 - trust * c * 0.5 ** (age / half_life))):
  high   C >= 75  -> <type>-high   (TI rule level 12)
  medium C >= 50  -> <type>-medium (TI rule level 8)
  low    C >= 20  -> not in a list: recorded for the 6.1c matcher only
  C < 20, a source's own expiry passed, or the hard TTL passed -> expired.
"""
import datetime as dt
import ipaddress

from sqlalchemy import text

from . import cdb, ti_rules

HALF_LIFE_DAYS = {"ipv4": 7, "ipv6": 7, "cidr4": 7, "cidr6": 7, "url": 14, "domain": 30, "md5": 180, "sha1": 180, "sha256": 180}
HARD_TTL_DAYS = {"ipv4": 30, "ipv6": 30, "cidr4": 30, "cidr6": 30, "url": 30, "domain": 90, "md5": 365, "sha1": 365, "sha256": 365}
DEFAULT_SOURCE_CONFIDENCE = 0.8
BANDS = ((75, "high"), (50, "medium"), (20, "low"))
NO_CROSS_TENANT_TLP = {"amber+strict", "red"}   # global intel with these TLPs is never matched for tenants
LIST_TYPE = {"ipv4": "ipv4", "cidr4": "ipv4", "ipv6": "ipv6", "domain": "domain", "url": "url",
             "md5": "md5", "sha1": "sha1", "sha256": "sha256"}           # cidr6: ti-matcher only


def score(sightings: list, typ: str, now: dt.datetime) -> int:
    """sightings: dicts with trust, source_confidence, last_seen, valid_until."""
    miss = 1.0
    for s in sightings:
        if s["valid_until"] and s["valid_until"] <= now:
            continue
        age = max((now - s["last_seen"]).total_seconds() / 86400, 0)
        c = s["source_confidence"] if s["source_confidence"] is not None else DEFAULT_SOURCE_CONFIDENCE
        miss *= 1 - s["trust"] * c * 0.5 ** (age / HALF_LIFE_DAYS[typ])
    return round(100 * (1 - miss))


def band(c: int) -> str:
    return next((name for floor, name in BANDS if c >= floor), "expired")


def cdb_keys(typ: str, value: str) -> list:
    """List keys for one IOC. An IPv4 CIDR becomes octet-aligned prefixes ("10.1.2.")
    that address_match_key understands, at most 256 of them; broader -> matcher only."""
    if typ != "cidr4":
        return [value]
    net = ipaddress.ip_network(value)
    octets = (net.prefixlen + 7) // 8           # round up to a whole octet
    if octets >= 4:
        hosts = [str(h) for h in net] if net.num_addresses <= 256 else []
        return hosts
    subnets = list(net.subnets(new_prefix=octets * 8))
    if len(subnets) > 256:
        return []
    return [".".join(str(sn.network_address).split(".")[:octets]) + "." for sn in subnets]


class Allow:
    def __init__(self, rows):
        self.exact, self.nets = set(), []
        for typ, value in rows:
            if typ in ("cidr4", "cidr6"):
                self.nets.append(ipaddress.ip_network(value))
            else:
                self.exact.add((LIST_TYPE.get(typ, typ), value))

    def blocks(self, typ: str, value: str) -> bool:
        if (LIST_TYPE.get(typ, typ), value) in self.exact:
            return True
        if typ in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(value)
            return any(ip in n for n in self.nets if n.version == ip.version)
        if typ in ("cidr4", "cidr6"):
            net = ipaddress.ip_network(value)
            # conservative: an IOC range that contains anything allowlisted is dropped whole
            return any(net.overlaps(n) for n in self.nets if n.version == net.version) or \
                any(t in ("ipv4", "ipv6") and ipaddress.ip_address(v) in net
                    for t, v in self.exact if t == LIST_TYPE[typ])
        return False


def evaluate(rows: list, allow: Allow, now: dt.datetime, stats: dict = None):
    """rows: one dict per live sighting (ioc_id, type, value, tenant_key, tlp, trust,
    source_confidence, last_seen, valid_until[, source]). Yields (ioc_id, type, value,
    confidence, band, sightings) for every IOC that is neither expired nor allowlisted -
    the one decision both the CDB lists and ti-matcher use."""
    stats = stats if stats is not None else {}
    by_ioc = {}
    for r in rows:
        if r["tenant_key"] is None and r["tlp"] in NO_CROSS_TENANT_TLP:
            continue
        by_ioc.setdefault(r["ioc_id"], []).append(r)
    for ioc_id, sightings in by_ioc.items():
        typ, value = sightings[0]["type"], sightings[0]["value"]
        last = max(s["last_seen"] for s in sightings)
        c = 0 if last + dt.timedelta(days=HARD_TTL_DAYS[typ]) <= now else score(sightings, typ, now)
        b = band(c)
        if b == "expired":
            stats["expired"] = stats.get("expired", 0) + 1
            continue
        if allow.blocks(typ, value):
            stats["allowlisted"] = stats.get("allowlisted", 0) + 1
            continue
        stats[b] = stats.get(b, 0) + 1
        yield ioc_id, typ, value, c, b, sightings


def expires_at(typ: str, sightings: list) -> dt.datetime:
    """When this IOC stops matching at the latest: the hard TTL, or the last source
    expiry if every source set one (§4.10). ti-matcher checks it at lookup time."""
    out = max(s["last_seen"] for s in sightings) + dt.timedelta(days=HARD_TTL_DAYS[typ])
    if all(s["valid_until"] for s in sightings):
        out = min(out, max(s["valid_until"] for s in sightings))
    return out


def select(rows: list, allow: Allow, now: dt.datetime) -> tuple:
    """-> ({list name: set(keys)}, {ioc_id: confidence}, stats)."""
    lists = {name: set() for name in ti_rules.list_names()}
    scores, stats = {}, {"high": 0, "medium": 0, "low": 0, "expired": 0, "allowlisted": 0, "matcher_only": 0}
    for ioc_id, typ, value, c, b, _ in evaluate(rows, allow, now, stats):
        scores[ioc_id] = c
        keys = cdb_keys(typ, value) if typ in LIST_TYPE else []
        if b == "low" or not keys:          # low band, IPv6 ranges, too-broad CIDRs
            stats["matcher_only"] += 1
            continue
        lists[f"{LIST_TYPE[typ]}-{b}"].update(keys)
    return lists, scores, stats


def load(conn, tenant_key: str, now: dt.datetime) -> tuple:
    """-> (live sighting rows, Allow) for one tenant: global + that tenant's private."""
    rows = conn.execute(text(
        "SELECT i.id AS ioc_id, i.type, i.value, i.tenant_key, s.tlp, src.trust, s.source_confidence, s.last_seen, "
        "s.valid_until, src.name AS source "
        "FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id JOIN ti_sources src ON src.id = s.source_id "
        "WHERE s.revoked_at IS NULL AND src.enabled AND (i.tenant_key IS NULL OR i.tenant_key = :t)"),
        {"t": tenant_key}).mappings().all()
    allow = Allow(conn.execute(text(
        "SELECT type, value FROM ti_allowlist WHERE (tenant_key IS NULL OR tenant_key = :t) "
        "AND (expires_at IS NULL OR expires_at > :now)"), {"t": tenant_key, "now": now}).all())
    return [dict(r) for r in rows], allow


def generate(conn, tenant_key: str, now: dt.datetime = None) -> tuple:
    """-> (bundle for safe_reload.apply, stats). Writes back each IOC's current confidence."""
    now = now or dt.datetime.now(dt.timezone.utc)
    rows, allow = load(conn, tenant_key, now)
    lists, scores, stats = select(rows, allow, now)
    for ioc_id, c in scores.items():
        conn.execute(text("UPDATE iocs SET confidence = :c WHERE id = :i AND confidence <> :c"), {"c": c, "i": ioc_id})
    files = {}
    for name, keys in lists.items():
        files[name] = cdb.write(keys) if keys else ti_rules.placeholder_list()
    stats["entries"] = {name: len(keys) for name, keys in lists.items() if keys}
    return ti_rules.bundle(files), stats
