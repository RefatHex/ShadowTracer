#!/usr/bin/env python3
"""Anonymises a raw alerts export (one Wazuh alert JSON per line) into a
fixture that is safe to commit, keeping every field's shape and size.

Replaced consistently (same input value -> same output everywhere in the file):
  IPv4      -> RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24,
               203.0.113/24), same string length where the ranges allow;
               loopback/0.0.0.0 kept. IPv6 (non-loopback) -> 2001:db8::/32.
  hostnames -> agent.name, manager.name, cluster.node, osquery host fields,
               predecoder.hostname, and wherever those names occur in text
               (full_log, data.extra_data, ...): same length, letters stay
               letters, digits stay digits, separators kept.
  usernames -> data.srcuser/dstuser and the sshd user slot in full_log, same
               length/shape. System accounts (root) are kept.
  agent ids -> same zero-padded shape; '000' (the manager itself) kept.
Nothing is rewritten under rule.* or data.sca.* (policy prose: CIS control
numbers such as 5.2.3.4 look like IPv4, "admin" appears in doc URLs).

The key is random per run unless --key is given; the mapping is not written
anywhere. A self-check runs after writing (see check()).

usage: anonymize.py RAW.jsonl OUT.jsonl [--key K]
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import string
import sys

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
SSHD_USER = re.compile(r"((?:[Ii]nvalid user|for invalid user|for|user) )(\S+)( from )")
# Policy/rule prose: CIS numbers look like IPv4 and words like "admin" appear in
# documentation URLs - neither is identity, so nothing is rewritten there.
PROSE = ("rule.", "data.sca.")
SSHD_TEXT = ("full_log", "previous_output")
KEEP_USERS = {"root"}
HOST_FIELDS = ("agent.name", "manager.name", "cluster.node", "data.osquery.hostIdentifier",
               "data.osquery.columns.hostname", "predecoder.hostname")
USER_FIELDS = ("data.srcuser", "data.dstuser")


class Anonymiser:
    def __init__(self, key: bytes):
        self.key = key
        self.ip4, self.ip6, self.hosts, self.users, self.ids = {}, {}, {}, {}, {}
        self._used_ip4 = set()

    def _stream(self, value: str, salt: str):
        i = 0
        while True:
            for b in hmac.new(self.key, f"{salt}|{value}|{i}".encode(), hashlib.sha256).digest():
                yield b
            i += 1

    def _shape(self, value: str, salt: str, taken: dict) -> str:
        """Same length; lower->lower, upper->upper, digit->digit, rest kept."""
        for attempt in range(100):
            s = self._stream(value, f"{salt}{attempt}")
            out = "".join(
                string.ascii_lowercase[next(s) % 26] if c.islower() else
                string.ascii_uppercase[next(s) % 26] if c.isupper() else
                string.digits[next(s) % 10] if c.isdigit() else c
                for c in value
            )
            if out != value and out not in taken.values():
                return out
        raise RuntimeError(f"no unique pseudonym for a {len(value)}-char value")

    def host(self, v):
        if v not in self.hosts:
            self.hosts[v] = self._shape(v, "host", self.hosts)
        return self.hosts[v]

    def user(self, v):
        if v in KEEP_USERS:
            return v
        if v not in self.users:
            self.users[v] = self._shape(v, "user", self.users)
        return self.users[v]

    def agent_id(self, v):
        if v == "000" or not v:
            return v
        if not v.isdigit():
            return self.host(v)
        if v not in self.ids:
            out = self._shape(v, "id", self.ids)
            while out == "000" * (len(out) // 3) or out in self.ids.values():
                out = self._shape(out, "id", self.ids)
            self.ids[v] = out
        return self.ids[v]

    def ipv4(self, v):
        ip = ipaddress.IPv4Address(v)
        if ip.is_loopback or ip.is_unspecified:
            return v
        if v not in self.ip4:
            prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")
            # Prefixes that can reach the original length with a 1-3 digit last octet.
            fitting = [p for p in prefixes if 1 <= len(v) - len(p) <= 3] or list(prefixes)
            s = self._stream(v, "ip4")
            for _ in range(5000):
                prefix = fitting[next(s) % len(fitting)]
                digits = min(max(len(v) - len(prefix), 1), 3)
                lo, hi = {1: (1, 9), 2: (10, 99), 3: (100, 254)}[digits]
                cand = prefix + str(lo + (next(s) << 8 | next(s)) % (hi - lo + 1))
                if cand not in self._used_ip4:
                    break
            else:
                raise RuntimeError("documentation IPv4 ranges exhausted")
            self._used_ip4.add(cand)
            self.ip4[v] = cand
        return self.ip4[v]

    def ipv6(self, v):
        try:
            ip = ipaddress.IPv6Address(v)
        except ValueError:
            return v
        if ip.is_loopback or ip.is_unspecified:
            return v
        if v not in self.ip6:
            self.ip6[v] = f"2001:db8::{len(self.ip6) + 1:x}"
        return self.ip6[v]


def walk(o, fn, path=""):
    if isinstance(o, dict):
        return {k: walk(v, fn, f"{path}.{k}" if path else k) for k, v in o.items()}
    if isinstance(o, list):
        return [walk(v, fn, path + "[]") for v in o]
    if isinstance(o, str):
        return fn(path, o)
    return o


def get(o, path):
    for k in path.split("."):
        if not isinstance(o, dict):
            return None
        o = o.get(k)
    return o


def anonymise(rows, an: Anonymiser):
    # Pass 1: learn every identity value from the structured fields, so text
    # occurrences get the same pseudonym no matter which line comes first.
    for r in rows:
        for f in HOST_FIELDS:
            if isinstance(get(r, f), str) and get(r, f):
                an.host(get(r, f))
        for f in USER_FIELDS:
            if isinstance(get(r, f), str) and get(r, f):
                an.user(get(r, f))
        for f in SSHD_TEXT:
            for m in SSHD_USER.finditer(r.get(f) or ""):
                an.user(m.group(2))
    host_re = _token_re(an.hosts)
    user_re = _token_re([u for u in an.users if u not in KEEP_USERS])

    def fn(path, s):
        if path == "agent.id":
            return an.agent_id(s)
        if path in USER_FIELDS:
            return an.user(s)
        if path in HOST_FIELDS:
            return an.host(s)
        if path.startswith(PROSE):
            return s
        if host_re:
            s = host_re.sub(lambda m: an.host(m.group(1)), s)
        if user_re:
            s = user_re.sub(lambda m: an.user(m.group(1)), s)
        s = IPV4.sub(lambda m: an.ipv4(m.group(0)) if _is_ip(m.group(0)) else m.group(0), s)
        return IPV6.sub(lambda m: an.ipv6(m.group(0)), s)

    return [walk(r, fn) for r in rows]


def _token_re(values):
    values = sorted(values, key=len, reverse=True)
    # A name may be followed by "->" (e.g. 'agent-x->any') but not by more name characters.
    return re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, values)) + r")(?!\w|-\w)") if values else None


def _is_ip(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def paths(o, p=""):
    if isinstance(o, dict):
        return {x for k, v in o.items() for x in paths(v, f"{p}.{k}" if p else k)} | {p}
    if isinstance(o, list):
        return {x for v in o for x in paths(v, p + "[]")} | {p}
    return {p}


def check(raw_rows, out_rows, raw_bytes, out_bytes, an: Anonymiser):
    """Fails loudly if anything identifying survived or a shape changed."""
    assert len(raw_rows) == len(out_rows), "line count changed"
    for a, b in zip(raw_rows, out_rows):
        assert paths(a) == paths(b), "field structure changed"
    texts = []
    for r in out_rows:
        walk(r, lambda p, v: texts.append(v) or v if not p.startswith(PROSE) else v)
    blob = "\n".join(texts)
    # Plain substring search - stricter than the token regex used to rewrite.
    leaks = [v for v in list(an.hosts) + [u for u in an.users if u not in KEEP_USERS] if v in blob]
    leaks += [ip for ip in an.ip4 if re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])", blob)
              and ip not in an.ip4.values()]
    leaks += [ip for ip in an.ip6 if ip in blob]
    assert not leaks, f"identity values still present: {leaks[:10]}"
    for a, b in zip(raw_rows, out_rows):
        for f in HOST_FIELDS + USER_FIELDS + ("agent.id", "agent.ip", "data.srcip"):
            x, y = get(a, f), get(b, f)
            if isinstance(x, str):
                assert len(x) == len(y) or f in ("agent.ip", "data.srcip"), f"{f} length changed"
    drift = (out_bytes - raw_bytes) / raw_bytes
    assert abs(drift) < 0.01, f"total size drifted {drift:.2%}"
    return drift


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("raw")
    p.add_argument("out")
    p.add_argument("--key", help="HMAC key (default: random, not stored)")
    a = p.parse_args()
    lines = [l for l in open(a.raw) if l.strip()]
    raw_rows = [json.loads(l) for l in lines]
    an = Anonymiser((a.key or secrets.token_hex(32)).encode())
    out_rows = anonymise(raw_rows, an)
    with open(a.out, "w") as f:
        for r in out_rows:
            f.write(json.dumps(r) + "\n")
    # Same serializer on both sides, so the drift measures value changes only.
    raw_bytes = sum(len((json.dumps(r) + "\n").encode()) for r in raw_rows)
    out_bytes = sum(len((json.dumps(r) + "\n").encode()) for r in out_rows)
    drift = check(raw_rows, out_rows, raw_bytes, out_bytes, an)
    print(f"{len(out_rows)} rows; replaced {len(an.ip4)} IPv4, {len(an.ip6)} IPv6, {len(an.hosts)} hostnames, "
          f"{len([u for u in an.users if u not in KEEP_USERS])} usernames, {len(an.ids)} agent ids; "
          f"bytes {raw_bytes} -> {out_bytes} ({drift:+.3%}); check OK", file=sys.stderr)


if __name__ == "__main__":
    main()
