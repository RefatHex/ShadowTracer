"""ti-matcher (6.1c): observable extraction, lookups, scoring parity with the CDB lists."""
import datetime as dt
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))
from shadowtracer_ingest.normalizer import normalize_alert  # noqa: E402

from shadowtracer_intel import listgen  # noqa: E402
from shadowtracer_intel.matcher import Hit, IocSet, Matcher, match, observables  # noqa: E402

NOW = dt.datetime(2026, 11, 6, 12, tzinfo=dt.timezone.utc)
LATER = NOW + dt.timedelta(days=30)
TENANT = "t1"


def alert(rule_id="5710", groups=("syslog", "sshd"), data=None, syscheck=None, alert_id="1.1"):
    a = {"timestamp": "2026-11-06T12:00:00.000+0000", "id": alert_id, "rule": {"id": rule_id, "level": 5, "groups": list(groups)},
         "agent": {"id": "001", "name": "a"}, "manager": {"name": "m"}, "cluster": {"node": "worker1"}, "full_log": "x"}
    if data is not None:
        a["data"] = data
    if syscheck is not None:
        a["syscheck"] = syscheck
    return normalize_alert(json.dumps(a), TENANT)


def hit(ioc_id, typ, value, c=80, expires=LATER):
    return Hit(ioc_id, typ, value, c, ("otx",), expires)


def test_observables_ips_urls_domains_hashes():
    ev = alert(data={"srcip": "45.33.32.157", "dstip": "::ffff:8.8.4.4", "srcport": "22",
                     "http": {"url": "hxxp://Evil.Example.COM:80/a?b=1#frag"}, "dns": {"queryName": "c2.bad.example"},
                     "url": "http://1.2.3.4/x"},
               syscheck={"sha256_after": "1F6CBFF1D91BD910B850AE4A7B34713C69A3C3D4B90A2507B176605B4E2258FE",
                         "md5_after": "not-a-hash"})
    got = {(t, v): f for f, t, v in observables(ev)}
    assert got[("ipv4", "45.33.32.157")] == "data.srcip"
    assert got[("ipv4", "8.8.4.4")] == "data.dstip"                     # IPv4-mapped IPv6 -> IPv4
    assert got[("url", "http://evil.example.com/a?b=1")] == "data.http.url"
    assert got[("domain", "evil.example.com")] == "data.http.url.host"
    assert got[("domain", "c2.bad.example")] == "data.dns.queryName"
    assert got[("ipv4", "1.2.3.4")] == "data.url.host"
    assert got[("sha256", "1f6cbff1d91bd910b850ae4a7b34713c69a3c3d4b90a2507b176605b4e2258fe")] == "syscheck.sha256_after"
    assert not any(t == "md5" for t, _ in got)                            # invalid values are dropped, never raise


def test_lookup_exact_cidr_parent_domain_and_expiry():
    s = IocSet([hit(1, "ipv4", "45.33.32.157"), hit(2, "cidr4", "10.20.0.0/16"), hit(3, "cidr6", "2001:db8::/32"),
                hit(4, "domain", "bad.example"), hit(5, "url", "http://evil.example.com/a"),
                hit(6, "ipv4", "45.33.32.158", expires=NOW - dt.timedelta(seconds=1))])
    assert [h.ioc_id for h in s.lookup("ipv4", "45.33.32.157", NOW)] == [1]
    assert [h.ioc_id for h in s.lookup("ipv4", "10.20.99.1", NOW)] == [2]
    assert [h.ioc_id for h in s.lookup("ipv6", "2001:db8:1::5", NOW)] == [3]
    assert [h.ioc_id for h in s.lookup("domain", "c2.bad.example", NOW)] == [4]   # parent domain
    assert s.lookup("domain", "example", NOW) == [] and s.lookup("domain", "notbad.example", NOW) == []
    assert [h.ioc_id for h in s.lookup("url", "http://evil.example.com/a", NOW)] == [5]
    assert s.lookup("ipv4", "45.33.32.158", NOW) == []                    # expired at lookup time
    assert s.by_type == {"ipv4": 2, "cidr4": 1, "cidr6": 1, "domain": 1, "url": 1}


def test_match_url_fixture_and_skip_ti_rule_alerts():
    s = IocSet([hit(5, "url", "http://evil.example.com/a", c=55), hit(4, "domain", "evil.example.com", c=90)])
    ev = alert(rule_id="31101", groups=("web",), data={"url": "http://EVIL.example.com/a"})
    rows = sorted(match(ev, s, NOW), key=lambda r: r["ioc_id"])
    assert [(r["ioc_id"], r["field"], r["confidence"]) for r in rows] == [(4, "data.url.host", 90), (5, "data.url", 55)]
    assert rows[0]["alert_id"] == "1.1" and rows[0]["node"] == "worker1" and rows[0]["tenant_key"] == TENANT
    ti = alert(rule_id="110001", groups=("sshd", "shadowtracer_ti", "ti_medium"), data={"url": "http://evil.example.com/a"})
    assert match(ti, s, NOW) == []


def test_from_rows_matches_list_generation_and_low_band():
    def row(ioc_id, typ, value, conf, source="otx", tenant=None, tlp="clear"):
        return {"ioc_id": ioc_id, "type": typ, "value": value, "tenant_key": tenant, "tlp": tlp, "trust": 1.0,
                "source_confidence": conf, "last_seen": NOW, "valid_until": None, "source": source}
    rows = [row(1, "ipv4", "45.33.32.157", 0.9), row(1, "ipv4", "45.33.32.157", 0.5, source="feodo"),
            row(2, "ipv4", "45.33.32.159", 0.3),                                    # low band: matcher only
            row(3, "ipv4", "1.1.1.1", 0.9), row(4, "ipv4", "45.33.32.160", 0.9, tlp="red")]
    allow = listgen.Allow([("ipv4", "1.1.1.1")])
    s = IocSet.from_rows(rows, allow, NOW, version=7)
    _, scores, _ = listgen.select(rows, allow, NOW)
    h = s.lookup("ipv4", "45.33.32.157", NOW)[0]
    assert h.confidence == scores[1] == 95 and h.sources == ("feodo", "otx")
    assert s.lookup("ipv4", "45.33.32.159", NOW)[0].confidence == 30
    assert s.lookup("ipv4", "1.1.1.1", NOW) == []                                 # allowlisted
    assert s.lookup("ipv4", "45.33.32.160", NOW) == []                            # global TLP:RED never matched
    assert s.version == 7 and s.size == 2


class Msg:
    def __init__(self, topic, value, offset=0):
        self._t, self._v, self._o = topic, value, offset

    def error(self):
        return None

    def topic(self):
        return self._t

    def value(self):
        return self._v

    def partition(self):
        return 0

    def offset(self):
        return self._o


def test_process_uses_topic_tenant_and_skips_unknown_and_bad():
    m = Matcher(None, None, None, lambda t: t.split(".")[2], lambda t: t in ("t1", "t2"), "test")
    m.sets = {"t1": IocSet([hit(1, "ipv4", "45.33.32.157")]), "t2": IocSet([])}
    good = json.dumps({"timestamp": "2026-11-06T12:00:00.000+0000", "id": "9.9", "rule": {"id": "5710", "groups": []},
                       "cluster": {"node": "w"}, "data": {"srcip": "45.33.32.157"}}).encode()
    rows = m.process([Msg("shadowtracer.t.t1.alerts", good), Msg("shadowtracer.t.t2.alerts", good),
                      Msg("shadowtracer.t.t3.alerts", good), Msg("shadowtracer.t.t1.alerts", b"{not json")])
    assert [(r["tenant_key"], r["ioc_id"]) for r in rows] == [("t1", 1)]       # t2's set has no such IOC
    assert m.stats["alerts"] == 2 and m.stats["skipped"] == 2


def test_tenants_share_one_global_set_minus_their_own_allowlist():
    """T17 (6.4): one shared global IocSet object; a tenant's allowlist hides a global IOC for
    that tenant only; private IOCs stay private."""
    from shadowtracer_intel.listgen import Allow
    from shadowtracer_intel.matcher import TenantIocs
    shared = IocSet([hit(1, "ipv4", "45.33.32.157"), hit(2, "cidr4", "10.20.0.0/16")])
    a = TenantIocs(shared, IocSet([hit(3, "ipv4", "45.33.32.170")]), Allow([("ipv4", "45.33.32.157")]))
    b = TenantIocs(shared, IocSet([]), Allow([]))
    assert a.shared is b.shared
    assert a.lookup("ipv4", "45.33.32.157", NOW) == [] and [h.ioc_id for h in b.lookup("ipv4", "45.33.32.157", NOW)] == [1]
    assert [h.ioc_id for h in a.lookup("ipv4", "45.33.32.170", NOW)] == [3] and b.lookup("ipv4", "45.33.32.170", NOW) == []
    assert [h.ioc_id for h in a.lookup("ipv4", "10.20.1.1", NOW)] == [2]
    assert (a.size, a.by_type) == (3, {"ipv4": 2, "cidr4": 1})
