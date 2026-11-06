"""Feed connectors: fetch (network, ti-sync only - never on the hot path) and parse.
A parser validates the WHOLE document first and raises FeedError on anything malformed,
so a bad feed is rejected whole and the store keeps the last good data
(THREAT_INTEL.md §4.12). Values are normalised later (normalise.py).
"""
import csv
import datetime as dt
import io
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "shadowtracer-ti-sync"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"        # CC0
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"           # CC0, deprecated upstream 2025-01-03
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
WARNINGLIST_URL = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/{name}/list.json"  # CC0
WARNINGLISTS = ("public-dns-v4", "public-dns-v6", "empty-hashes")


class FeedError(Exception):
    pass


class RateLimited(FeedError):
    """HTTP 429. retry_after: seconds from the Retry-After header, if any."""

    def __init__(self, msg, retry_after=None):
        super().__init__(msg)
        self.retry_after = retry_after


@dataclass(slots=True)          # 6.2: 126k-entry lists; a __dict__ per entry OOM-killed ti-sync at 256m
class Observation:
    type_hint: str
    value: str
    source_ref: str
    reference_url: str = None
    source_info: str = None              # e.g. MISP event info
    source_confidence: float = None      # 0-1; None = source gives none
    tlp: str = "clear"
    labels: list = field(default_factory=list)
    mitre: list = field(default_factory=list)
    first_seen: dt.datetime = None
    last_seen: dt.datetime = None
    valid_until: dt.datetime = None


def fetch(url: str, headers: dict = None, timeout: float = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        # The URL is logged without its query; credentials only ever travel in headers.
        if exc.code == 429:
            ra = (exc.headers.get("Retry-After") or "").strip()
            raise RateLimited(f"fetch {url.split('?')[0]}: HTTP 429", float(ra) if ra.isdigit() else None) from exc
        raise FeedError(f"fetch {url.split('?')[0]}: HTTP {exc.code}") from exc
    except Exception as exc:  # noqa: BLE001 - any transport failure is a feed failure
        raise FeedError(f"fetch {url.split('?')[0]}: {type(exc).__name__}: {exc}") from exc


def _ts(s, fmt):
    return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc) if s else None


def parse_feodo(raw: bytes) -> list:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"feodo: not JSON: {exc}")
    if not isinstance(data, list) or not all(isinstance(e, dict) and isinstance(e.get("ip_address"), str) for e in data):
        raise FeedError("feodo: expected a list of objects with ip_address")
    out = []
    for e in data:
        try:
            first = _ts(e.get("first_seen"), "%Y-%m-%d %H:%M:%S")
            last = _ts(e.get("last_online"), "%Y-%m-%d") or first
        except ValueError as exc:
            raise FeedError(f"feodo: bad date: {exc}")
        online = e.get("status") == "online"
        out.append(Observation(
            "ipv4", e["ip_address"], source_ref=e["ip_address"],
            reference_url=f"https://feodotracker.abuse.ch/browse/host/{e['ip_address']}/",
            source_confidence=0.95 if online else 0.6, tlp="clear",
            labels=[l for l in ("botnet_cc", e.get("malware")) if l], first_seen=first, last_seen=last))
    return out


def parse_sslbl(raw: bytes) -> list:
    text = raw.decode("utf-8", "replace")
    if "abuse.ch" not in text[:400]:
        raise FeedError("sslbl: missing the abuse.ch header")
    out = []
    for row in csv.reader(l for l in io.StringIO(text) if l.strip() and not l.startswith("#")):
        if len(row) != 3:
            raise FeedError(f"sslbl: expected Firstseen,DstIP,DstPort, got {row!r}")
        try:
            first = _ts(row[0], "%Y-%m-%d %H:%M:%S")
        except ValueError as exc:
            raise FeedError(f"sslbl: bad date: {exc}")
        out.append(Observation("ipv4", row[1], source_ref=row[1],
                               reference_url="https://sslbl.abuse.ch/blacklist/",
                               source_confidence=0.8, labels=["botnet_cc"], first_seen=first, last_seen=first))
    return out


OTX_TYPES = {"IPv4": "ipv4", "IPv6": "ipv6", "domain": "domain", "hostname": "domain", "URL": "url",
             "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256", "CIDR": "cidr4"}
OTX_TLP = {"white": "clear", "clear": "clear", "green": "green", "amber": "amber", "red": "red"}


def _otx_time(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise FeedError(f"otx: bad time {s!r}: {exc}")


def parse_otx_page(raw: bytes) -> tuple:
    """One page of /api/v1/pulses/subscribed -> (observations, next_url, max_modified)."""
    try:
        page = json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"otx: not JSON: {exc}")
    pulses = page.get("results") if isinstance(page, dict) else None
    if not isinstance(pulses, list) or not all(isinstance(p, dict) and isinstance(p.get("id"), str)
                                               and isinstance(p.get("indicators"), list) for p in pulses):
        raise FeedError("otx: expected results[] of pulses with id and indicators[]")
    out, newest = [], None
    for p in pulses:
        tlp = OTX_TLP.get(str(p.get("tlp", "white")).lower())
        if tlp is None:
            raise FeedError(f"otx: unknown TLP {p.get('tlp')!r}")
        modified = _otx_time(p.get("modified"))
        newest = max(filter(None, [newest, modified]), default=None)
        labels = list(p.get("tags") or []) + [m.get("display_name") for m in p.get("malware_families") or [] if isinstance(m, dict)]
        mitre = [a.get("id") for a in p.get("attack_ids") or [] if isinstance(a, dict) and a.get("id")]
        for ind in p["indicators"]:
            if not isinstance(ind, dict) or "indicator" not in ind or "type" not in ind:
                raise FeedError(f"otx: malformed indicator in pulse {p['id']}")
            t = OTX_TYPES.get(ind["type"])
            if t is None or ind.get("is_active") == 0:
                continue                       # email, CVE, mutex, ...: not matchable here
            out.append(Observation(
                t, ind["indicator"], source_ref=p["id"],
                reference_url=f"https://otx.alienvault.com/pulse/{p['id']}", tlp=tlp,
                labels=[l for l in labels if l], mitre=mitre,
                first_seen=_otx_time(ind.get("created")) or modified,
                last_seen=modified or _otx_time(ind.get("created")),
                valid_until=_otx_time(ind.get("expiration"))))
    nxt = page.get("next")
    return out, (nxt if isinstance(nxt, str) and nxt else None), newest


def fetch_otx(api_key: str, modified_since: str = None, max_pages: int = 200, retries: int = 4,
              sleep=time.sleep) -> tuple:
    """Subscribed pulses only, every page modified since the cursor. Returns
    (observations, new cursor). HTTP 429: wait (Retry-After, else 30 s doubling, at most
    10 min) and retry the same page; after `retries` waits the sync fails and the store
    and cursor stay as they were (§4.12)."""
    url = OTX_URL + "?limit=50" + (f"&modified_since={modified_since}" if modified_since else "")
    obs, cursor = [], modified_since
    for _ in range(max_pages):
        for attempt in range(retries + 1):
            try:
                raw = fetch(url, {"X-OTX-API-KEY": api_key}, timeout=60)
                break
            except RateLimited as exc:
                if attempt == retries:
                    raise
                sleep(min(max(exc.retry_after or 0, 30 * 2 ** attempt), 600))
        page_obs, url, newest = parse_otx_page(raw)
        obs += page_obs
        if newest and (cursor is None or newest.isoformat() > cursor):
            cursor = newest.isoformat()
        if not url:
            return obs, cursor
    raise FeedError(f"otx: more than {max_pages} pages; raise max_pages or sync more often")


def parse_warninglist(raw: bytes) -> tuple:
    """-> (name, [(type_hint, value)]). CIDR lists give IPs/CIDRs; string lists
    (empty-hashes) give hashes by length."""
    try:
        wl = json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"warninglist: not JSON: {exc}")
    if not isinstance(wl, dict) or not isinstance(wl.get("list"), list) or not wl.get("name"):
        raise FeedError("warninglist: expected name and list[]")
    by_len = {32: "md5", 40: "sha1", 64: "sha256"}
    entries = []
    for v in wl["list"]:
        if not isinstance(v, str):
            continue
        if wl.get("type") == "cidr":
            entries.append(("ipv6" if ":" in v else "ipv4", v))
        elif len(v) in by_len:
            entries.append((by_len[len(v)], v))
    return wl["name"], entries


# --- 6.2: MISP feeds (manifest.json + one <uuid>.json per event) ----------------------

# MISP attribute type -> our type hint. Composite "ip|port" and "filename|hash" carry the
# same observable in their first/second half.
MISP_TYPES = {"ip-src": "ipv4", "ip-dst": "ipv4", "ip-src|port": "ipv4", "ip-dst|port": "ipv4",
              "domain": "domain", "hostname": "domain", "url": "url",
              "md5": "md5", "sha1": "sha1", "sha256": "sha256",
              "filename|md5": "md5", "filename|sha1": "sha1", "filename|sha256": "sha256"}
MISP_TLP = {"tlp:white": "clear", "tlp:clear": "clear", "tlp:green": "green", "tlp:amber": "amber",
            "tlp:amber+strict": "amber+strict", "tlp:red": "red"}
# MISP threat_level_id -> source confidence (1 high, 2 medium, 3 low, 4 undefined)
MISP_THREAT_CONFIDENCE = {"1": 0.9, "2": 0.75, "3": 0.5, "4": 0.6}
_MITRE = __import__("re").compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _misp_value(attr_type: str, value: str) -> str:
    if "|" not in attr_type:
        return value
    left, _, right = value.partition("|")
    return left if attr_type.endswith("|port") else right


def parse_misp_manifest(raw: bytes) -> dict:
    """-> {event uuid: event timestamp (int)}."""
    try:
        m = json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"misp manifest: not JSON: {exc}")
    if not isinstance(m, dict) or not all(isinstance(v, dict) and str(v.get("timestamp", "")).isdigit() for v in m.values()):
        raise FeedError("misp manifest: expected {uuid: {timestamp, ...}}")
    return {k: int(v["timestamp"]) for k, v in m.items()}


def _tags(obj) -> list:
    return [t.get("name", "") for t in (obj.get("Tag") or []) if isinstance(t, dict)]


def misp_attributes_to_observations(attrs, event: dict, reference_url: str, default_tlp: str) -> list:
    """to_ids attributes of the matchable types -> Observations. Attribute tags override
    the event's TLP; every non-TLP tag becomes a label, MITRE technique ids go to mitre."""
    ev_tags = _tags(event)
    ev_tlp = next((MISP_TLP[t.lower()] for t in ev_tags if t.lower() in MISP_TLP), default_tlp)
    out = []
    for a in attrs:
        if not isinstance(a, dict) or "type" not in a or "value" not in a:
            raise FeedError(f"misp: malformed attribute in event {event.get('uuid')}")
        t = MISP_TYPES.get(a["type"])
        if t is None or not a.get("to_ids") or a.get("deleted"):
            continue
        a_tags = _tags(a)
        tlp = next((MISP_TLP[x.lower()] for x in a_tags if x.lower() in MISP_TLP), ev_tlp)
        tags = [x for x in ev_tags + a_tags if x and x.lower() not in MISP_TLP]
        seen = _ts_epoch(a.get("timestamp")) or _ts_epoch(event.get("timestamp"))
        out.append(Observation(
            t, _misp_value(a["type"], str(a["value"])), source_ref=f"misp-event:{event.get('uuid')}",
            reference_url=reference_url, source_info=str(event.get("info", ""))[:500],
            source_confidence=MISP_THREAT_CONFIDENCE.get(str(event.get("threat_level_id")), 0.6),
            tlp=tlp, labels=sorted(set(tags)), mitre=sorted({m for x in tags for m in _MITRE.findall(x)}),
            first_seen=_otx_time(a.get("first_seen")) or seen, last_seen=_otx_time(a.get("last_seen")) or seen))
    return out


def _ts_epoch(v):
    return dt.datetime.fromtimestamp(int(v), dt.timezone.utc) if v and str(v).isdigit() else None


def parse_misp_event(raw: bytes, reference_url: str, default_tlp: str = "clear") -> list:
    try:
        ev = json.loads(raw)["Event"]
    except (ValueError, KeyError, TypeError) as exc:
        raise FeedError(f"misp event: expected {{Event: ...}}: {exc}")
    if not isinstance(ev, dict) or not isinstance(ev.get("Attribute", []), list):
        raise FeedError("misp event: Event.Attribute must be a list")
    attrs = list(ev.get("Attribute") or []) + [a for o in ev.get("Object") or [] if isinstance(o, dict)
                                               for a in o.get("Attribute") or []]
    return misp_attributes_to_observations(attrs, ev, reference_url, default_tlp)


# --- 6.2: plain lists -----------------------------------------------------------------

SPAMHAUS_DROP_URLS = {"ipv4": "https://www.spamhaus.org/drop/drop_v4.json",
                      "ipv6": "https://www.spamhaus.org/drop/drop_v6.json"}


def parse_spamhaus_drop(raw: bytes) -> list:
    """JSON lines {"cidr", "sblid", "rir"} and a final metadata line (copyright, terms):
    a download without the metadata line is truncated and rejected."""
    out, meta = [], None
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            raise FeedError(f"spamhaus drop: bad line: {exc}")
        if rec.get("type") == "metadata":
            meta = rec
        elif isinstance(rec.get("cidr"), str):
            out.append(Observation("cidr4" if ":" not in rec["cidr"] else "cidr6", rec["cidr"],
                                   source_ref=str(rec.get("sblid", "")),
                                   reference_url=f"https://check.spamhaus.org/sbl/query/{rec.get('sblid', '')}",
                                   source_confidence=0.95, labels=["spamhaus-drop"]))
    if not meta or "copyright" not in meta:
        raise FeedError("spamhaus drop: no metadata line (truncated download?)")
    return out


def parse_list(raw: bytes, type_hint: str, label: str, min_entries: int = 1, confidence: float = None,
               sep: str = None, column: int = 0) -> list:
    """One observable per line; '#' and ';' comments, blank lines skipped; the first
    whitespace/','/';'-separated token is the value. An HTML page (an error or
    maintenance page served with 200) or a list below min_entries is rejected whole.
    sep/column: take field `column` of a `sep`-separated line instead (dataplane.org:
    "ASN | AS name | IP | last seen | category")."""
    text_ = raw.decode("utf-8", errors="replace")
    if text_.lstrip()[:1] == "<":
        raise FeedError(f"{label}: got HTML, not a list")
    out, labels = [], (label,)                      # one shared labels tuple for the whole list
    for line in text_.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if sep:
            fields = [f.strip() for f in line.split(sep)]
            if len(fields) <= column:
                raise FeedError(f"{label}: expected at least {column + 1} '{sep}'-separated fields")
            value = fields[column]
        else:
            value = line.replace(",", " ").replace(";", " ").split()[0]
        out.append(Observation(type_hint, value, source_ref=label, source_confidence=confidence, labels=labels))
    if len(out) < min_entries:
        raise FeedError(f"{label}: {len(out)} entries, expected at least {min_entries}")
    return out
