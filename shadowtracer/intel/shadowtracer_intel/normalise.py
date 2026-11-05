"""Feed values are untrusted input. Normalise to one canonical form per type, or reject.
THREAT_INTEL.md §4.6 (normalisation) and §4.7 (nothing that could break CDB syntax gets
through; a value is rejected, never escaped).

Types: ipv4, ipv6, cidr4, cidr6, domain, url, md5, sha1, sha256.
scope: "global" rejects non-routable addresses (RFC 1918, loopback, link-local, CGNAT,
documentation, multicast, reserved); "tenant" (tenant-private intel) allows them.
"""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

TYPES = ("ipv4", "ipv6", "cidr4", "cidr6", "domain", "url", "md5", "sha1", "sha256")
EMPTY_FILE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
_HASH = {"md5": 32, "sha1": 40, "sha256": 64}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DEFANG = [(re.compile(r"hxxp", re.I), "http"), (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."),
           (re.compile(r"\[:\]"), ":"), (re.compile(r"\[@\]|\[at\]", re.I), "@")]
_LEFTOVER = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|hxxp", re.I)
MIN_PREFIX = {4: 16, 6: 32}     # broader CIDRs are rejected from feeds (poisoning guard)
MAX_URL = 2048


class Rejected(ValueError):
    pass


def refang(raw: str) -> str:
    s = raw.strip()
    for pat, rep in _DEFANG:
        s = pat.sub(rep, s)
    return s


def _no_cdb_breakers(s: str) -> None:
    # The CDB text format is line-based "key:value" (lists_make.c): a newline adds an
    # entry, a quote or NUL truncates or skips one. None of these is ever legitimate in
    # a normalised IOC, so reject outright instead of escaping.
    if any(ord(c) < 0x21 or ord(c) == 0x7f or c == '"' for c in s):
        raise Rejected("control character, whitespace or quote")


def _ip(s: str, scope: str):
    try:
        ip = ipaddress.ip_address(s)          # rejects leading zeros ("010.1.1.1")
    except ValueError:
        raise Rejected("not an IP address")
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if scope == "global" and (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        raise Rejected("non-routable address in global intel")
    return ip


def normalise(type_: str, raw: str, scope: str = "global") -> tuple:
    """Returns (type, canonical value). type may be refined (ipv6 that is IPv4-mapped
    becomes ipv4; ipv4 given with a /n becomes cidr4)."""
    if type_ not in TYPES:
        raise Rejected(f"unknown type {type_!r}")
    if not isinstance(raw, str) or not raw or len(raw) > MAX_URL:
        raise Rejected("empty or too long")
    s = refang(raw)
    if _LEFTOVER.search(s):
        raise Rejected("still defanged after refang")
    _no_cdb_breakers(s)

    if type_ in ("ipv4", "ipv6") and "/" not in s:
        ip = _ip(s, scope)
        return ("ipv4" if ip.version == 4 else "ipv6"), str(ip)
    if type_ in ("ipv4", "ipv6", "cidr4", "cidr6"):
        try:
            net = ipaddress.ip_network(s, strict=False)       # host bits masked off
        except ValueError:
            raise Rejected("not a CIDR")
        if net.prefixlen < MIN_PREFIX[net.version]:
            raise Rejected(f"CIDR broader than /{MIN_PREFIX[net.version]}")
        if scope == "global" and not all(a.is_global and not a.is_multicast and not a.is_reserved
                                         for a in (net.network_address, net.broadcast_address)):
            raise Rejected("non-routable range in global intel")
        if net.num_addresses == 1:
            return ("ipv4" if net.version == 4 else "ipv6"), str(net.network_address)
        return ("cidr4" if net.version == 4 else "cidr6"), str(net)
    if type_ in _HASH:
        h = s.lower()
        if len(h) != _HASH[type_] or not re.fullmatch(r"[0-9a-f]+", h):
            raise Rejected(f"not a {type_}")
        if h in EMPTY_FILE_HASHES:
            raise Rejected("hash of the empty file")
        return type_, h
    if type_ == "domain":
        return "domain", _domain(s)
    return "url", _url(s)


def _domain(s: str) -> str:
    d = s.lower().rstrip(".")
    if d.startswith("*."):
        raise Rejected("wildcard domain (ti-matcher only)")
    try:
        d = d.encode("idna").decode("ascii")   # stdlib IDNA 2003 -> punycode A-labels
    except UnicodeError:
        raise Rejected("not a valid domain")
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
        raise Rejected("not a valid domain")
    if labels[-1].isdigit():
        raise Rejected("numeric TLD (an IP?)")
    return d


def _url(s: str) -> str:
    try:
        parts = urlsplit(s)
    except ValueError:
        raise Rejected("not a URL")
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        raise Rejected("URL needs http/https/ftp and a host")
    host = parts.hostname
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = _domain(host)
    port = parts.port
    default = {"http": 80, "https": 443, "ftp": 21}[parts.scheme.lower()]
    netloc = host if port in (None, default) else f"{host}:{port}"
    if ":" in host:
        netloc = f"[{host}]" if port in (None, default) else f"[{host}]:{port}"
    url = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    if len(url) > MAX_URL:
        raise Rejected("URL too long")
    _no_cdb_breakers(url)
    return url
