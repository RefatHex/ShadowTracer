"""Feed parsers (whole-feed rejection) and list generation (bands, decay, TLP,
allowlists, CIDR expansion, multi-source dedup)."""
import datetime as dt
import json
import os

import pytest

from shadowtracer_intel import feeds, listgen, ti_rules

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
NOW = dt.datetime(2026, 11, 6, tzinfo=dt.timezone.utc)


def raw(name):
    return open(os.path.join(FIX, name), "rb").read()


def test_feodo_real_format():
    obs = feeds.parse_feodo(raw("feodo_ipblocklist.json"))
    assert len(obs) == 5 and all(o.type_hint == "ipv4" and o.reference_url.startswith("https://feodotracker.abuse.ch/") for o in obs)


@pytest.mark.parametrize("bad", [b"not json", b'{"ip_address": "1.2.3.4"}', b'[{"ip": "1.2.3.4"}]',
                                 b'[{"ip_address": "45.33.32.156", "first_seen": "yesterday"}]'])
def test_malformed_feed_is_rejected_whole(bad):
    with pytest.raises(feeds.FeedError):
        feeds.parse_feodo(bad)


def test_sslbl_deprecated_list_has_no_entries():
    assert feeds.parse_sslbl(raw("sslbl_sslipblacklist.csv")) == []
    with pytest.raises(feeds.FeedError):
        feeds.parse_sslbl(b"<html>404</html>")


def test_otx_page():
    obs, nxt, newest = feeds.parse_otx_page(raw("otx_pulses_page.json").replace(b"MODIFIED_PLACEHOLDER", b"2026-11-05T00:00:00"))
    assert nxt is None and newest.isoformat().startswith("2026-11-05")
    types = sorted({o.type_hint for o in obs})
    assert types == ["domain", "ipv4", "sha256", "url"]           # email skipped
    ip = next(o for o in obs if o.value == "45.33.32.157")
    assert ip.mitre == ["T1071"] and "LabRAT" in ip.labels and ip.tlp == "clear"
    assert ip.reference_url == "https://otx.alienvault.com/pulse/6720f0c1a1b2c3d4e5f60718"
    with pytest.raises(feeds.FeedError):
        feeds.parse_otx_page(b'{"results": [{"id": "x"}]}')      # pulse without indicators[]


def test_warninglists():
    name, entries = feeds.parse_warninglist(raw("warninglist_public-dns-v4.json"))
    assert "public DNS" in name and ("ipv4", "1.1.1.1") in entries
    _, hashes = feeds.parse_warninglist(raw("warninglist_empty-hashes.json"))
    assert {t for t, _ in hashes} >= {"md5", "sha1", "sha256"}


def row(ioc_id, typ, value, trust=0.8, c=0.95, days_ago=0, tenant=None, tlp="clear", valid_until=None):
    return {"ioc_id": ioc_id, "type": typ, "value": value, "tenant_key": tenant, "tlp": tlp, "trust": trust,
            "source_confidence": c, "last_seen": NOW - dt.timedelta(days=days_ago), "valid_until": valid_until}


def test_bands_decay_and_expiry():
    assert listgen.score([row(1, "ipv4", "x")], "ipv4", NOW) == 76                       # Feodo online: high
    assert listgen.score([row(1, "ipv4", "x", trust=0.7, c=None)], "ipv4", NOW) == 56    # OTX default: medium
    assert listgen.score([row(1, "ipv4", "x", days_ago=7)], "ipv4", NOW) == 38           # one half-life later: low
    assert listgen.score([row(1, "ipv4", "x", valid_until=NOW)], "ipv4", NOW) == 0       # source expiry passed
    lists, scores, stats = listgen.select([row(1, "ipv4", "45.33.32.156", days_ago=31)], listgen.Allow([]), NOW)
    assert stats["expired"] == 1 and not lists["ipv4-high"]                              # hard TTL (30 d) passed


def test_one_entry_per_observable_and_sources_combine():
    rows = [row(1, "ipv4", "45.33.32.156", trust=0.7, c=None), row(1, "ipv4", "45.33.32.156", trust=0.8, c=0.95)]
    lists, scores, _ = listgen.select(rows, listgen.Allow([]), NOW)
    assert scores[1] == 89 and lists["ipv4-high"] == {"45.33.32.156"} and not lists["ipv4-medium"]


def test_allowlists_tlp_and_cidr():
    allow = listgen.Allow([("ipv4", "1.1.1.1"), ("cidr4", "8.8.8.0/24"), ("sha256", "a" * 64)])
    rows = [row(1, "ipv4", "1.1.1.1"), row(2, "ipv4", "8.8.8.8"), row(3, "sha256", "a" * 64),
            row(4, "cidr4", "45.33.32.0/20"), row(5, "ipv4", "45.33.32.160", tlp="red"),
            row(6, "ipv4", "45.33.32.161", tenant="t1", tlp="red"), row(7, "cidr4", "8.8.0.0/16")]
    lists, _, stats = listgen.select(rows, allow, NOW)
    high = lists["ipv4-high"]
    assert "1.1.1.1" not in high and "8.8.8.8" not in high and not lists["sha256-high"]
    assert stats["allowlisted"] == 4                                                     # incl. the /16 that contains 8.8.8.0/24
    assert {"45.33.32.", "45.33.47."} <= high and len([k for k in high if k.startswith("45.33.")]) == 17  # /20 -> 16 x /24 + the tenant IP
    assert "45.33.32.160" not in high                                                     # global TLP:RED never matched
    assert "45.33.32.161" in high                                                         # tenant-private red: own tenant only


def test_generated_bundle_has_every_list():
    names = set(ti_rules.list_names())
    lists, _, _ = listgen.select([], listgen.Allow([]), NOW)
    assert set(lists) == names
