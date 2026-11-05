"""Feed connectors: fetch (network, ti-sync only - never on the hot path) and parse.
A parser validates the WHOLE document first and raises FeedError on anything malformed,
so a bad feed is rejected whole and the store keeps the last good data
(THREAT_INTEL.md §4.12). Values are normalised later (normalise.py).
"""
import csv
import datetime as dt
import io
import json
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


@dataclass
class Observation:
    type_hint: str
    value: str
    source_ref: str
    reference_url: str = None
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


def fetch_otx(api_key: str, modified_since: str = None, max_pages: int = 200) -> tuple:
    """All pages since the cursor. Returns (observations, new cursor)."""
    url = OTX_URL + "?limit=50" + (f"&modified_since={modified_since}" if modified_since else "")
    obs, cursor = [], modified_since
    for _ in range(max_pages):
        page_obs, url, newest = parse_otx_page(fetch(url, {"X-OTX-API-KEY": api_key}, timeout=60))
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
