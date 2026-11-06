"""6.2: MISP feeds, tenant MISP server connector, free list feeds, TLP rule, feed defaults."""
import datetime as dt
import json
import os

import pytest
import responses

from shadowtracer_intel import feeds, misp_server, store, sync
from shadowtracer_intel.feeds import FeedError, Observation
from shadowtracer_intel.normalise import Rejected, normalise

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
NOW = dt.datetime(2026, 11, 6, 12, tzinfo=dt.timezone.utc)


def fixture(name) -> bytes:
    return open(os.path.join(FIX, name), "rb").read()


def test_misp_event_to_ids_types_composites_objects_tags():
    obs = feeds.parse_misp_event(fixture("misp_feed_event.json"), "https://feed/e1.json")
    got = {(o.type_hint, o.value): o for o in obs}
    assert set(got) == {("ipv4", "45.33.32.198"), ("ipv4", "45.33.32.199"), ("domain", "c2.example-bad.com"),
                        ("url", "hxxp://example-bad[.]com/gate.php"), ("ipv4", "192.0.2.10"),
                        ("sha256", "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"),
                        ("md5", "0cc175b9c0f1b6a831c399e269772661")}      # not: to_ids false, email, deleted, imphash
    o = got[("ipv4", "45.33.32.198")]
    assert o.tlp == "clear" and o.source_ref == "misp-event:5f0c1a2b-0000-4000-8000-000000000001"
    assert o.source_info == "OSINT - Example C2 infrastructure" and o.source_confidence == 0.9
    assert o.mitre == ["T1071"] and 'osint:source-type="blog-post"' in o.labels
    assert o.last_seen == dt.datetime.fromtimestamp(1793390000, dt.timezone.utc)   # the attribute's own time
    assert got[("ipv4", "192.0.2.10")].tlp == "amber"                               # attribute tag overrides event


def test_misp_manifest_and_malformed_documents():
    m = feeds.parse_misp_manifest(fixture("misp_feed_manifest.json"))
    assert m["5f0c1a2b-0000-4000-8000-000000000002"] == 1793400100 and len(m) == 3
    for bad in (b"<html>", b'{"x": {"info": "no timestamp"}}'):
        with pytest.raises(FeedError):
            feeds.parse_misp_manifest(bad)
    with pytest.raises(FeedError):
        feeds.parse_misp_event(b'{"Event": {"Attribute": "nope"}}', "u")


def test_tlp_amber_and_red_are_never_global_but_stay_tenant_private():
    red = feeds.parse_misp_event(fixture("misp_feed_event_tlp_red.json"), "u")
    ok = feeds.parse_misp_event(fixture("misp_feed_event.json"), "u")
    rows, counts = store.prepare_rows(red + ok, None, NOW)
    assert counts["rejected"] == {"TLP:RED is never global": 1, "TLP:AMBER is never global": 1}
    assert ("ipv4", "45.33.32.201") not in rows and ("ipv4", "45.33.32.198") in rows
    rows, counts = store.prepare_rows(red, "tenant-a", NOW)                       # tenant-private: kept
    assert rows[("ipv4", "45.33.32.201")].tlp == "red" and not counts["rejected"]


def test_merge_keeps_widest_time_most_restrictive_tlp_and_all_labels():
    t1, t2 = NOW - dt.timedelta(days=3), NOW - dt.timedelta(days=1)
    rows, _ = store.prepare_rows([
        Observation("ipv4", "45.33.32.157", "p1", tlp="clear", labels=["a"], first_seen=t1, last_seen=t1),
        Observation("ipv4", "45.33.32.157", "p2", tlp="green", labels=["b"], first_seen=t2, last_seen=t2, source_info="newest")],
        None, NOW)
    r = rows[("ipv4", "45.33.32.157")]
    assert (r.first_seen, r.last_seen, r.tlp, r.labels, r.source_ref, r.source_info) == \
        (t1, t2, "green", {"a", "b"}, "p2", "newest")


def test_spamhaus_drop_needs_metadata_and_allows_broad_ranges():
    raw = (b'{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n{"cidr":"45.8.0.0/11","sblid":"SBL1","rir":"ripencc"}\n'
           b'{"type":"metadata","timestamp":1793898842,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}\n')
    obs = feeds.parse_spamhaus_drop(raw)
    assert [(o.type_hint, o.value, o.source_ref) for o in obs] == [("cidr4", "1.10.16.0/20", "SBL256894"), ("cidr4", "45.8.0.0/11", "SBL1")]
    with pytest.raises(FeedError):
        feeds.parse_spamhaus_drop(raw.rsplit(b"\n", 2)[0])                        # truncated: no metadata line
    with pytest.raises(Rejected):
        normalise("cidr4", "45.8.0.0/11")                                          # default guard: /16
    assert normalise("cidr4", "45.8.0.0/11", min_prefix={4: 8, 6: 16}) == ("cidr4", "45.0.0.0/11")


def test_parse_list_comments_html_and_minimum():
    obs = feeds.parse_list(b"# header\n; note\n45.33.32.1\n45.33.32.2 # trailing\n\n45.33.32.3,extra\n", "ipv4", "x", 3)
    assert [o.value for o in obs] == ["45.33.32.1", "45.33.32.2", "45.33.32.3"]
    with pytest.raises(FeedError):
        feeds.parse_list(b"<html><body>503</body></html>", "ipv4", "x")
    with pytest.raises(FeedError):
        feeds.parse_list(b"45.33.32.1\n", "ipv4", "x", min_entries=1000)
    dp = b"# Dataplane.org\n174    |  COGENT-174  |  45.33.32.5  |  2026-11-05 22:01:02  |  sshpwauth\n"
    assert [o.value for o in feeds.parse_list(dp, "ipv4", "dp", sep="|", column=2)] == ["45.33.32.5"]


def test_feed_defaults_follow_licences_and_env_overrides():
    on = {f.name for f in sync.sources_from_env({}) if f.default_on}
    assert on == {"abusech-feodo", "spamhaus-drop-v4", "spamhaus-drop-v6", "certpl-domains"}
    env = {"TI_FEED_CIRCL_OSINT": "1", "TI_FEED_CERTPL_DOMAINS": "0"}
    on = {f.name for f in sync.sources_from_env(env) if f.default_on}
    assert "circl-osint" in on and "certpl-domains" not in on
    assert all(f.licence for f in sync.FEEDS)
    drop = next(f for f in sync.FEEDS if f.name == "spamhaus-drop-v4")
    assert drop.min_interval >= dt.timedelta(days=1)                              # DROP terms: max once a day


MISP_URL = "https://misp.tenant-a.example"


def _mock_misp_init(rsps):
    rsps.add(responses.GET, f"{MISP_URL}/servers/getPyMISPVersion.json", json={"version": "2.5.34"})
    rsps.add(responses.GET, f"{MISP_URL}/servers/getVersion", json={"version": "2.5.34", "perm_sync": False})
    rsps.add(responses.GET, f"{MISP_URL}/users/view/me", json={
        "User": {"id": "5", "email": "sync@tenant-a.example", "org_id": "1", "role_id": "3"},
        "Role": {"id": "3", "name": "read only", "perm_auth": True}, "UserSetting": {}})
    rsps.add(responses.GET, f"{MISP_URL}/attributes/describeTypes.json", json={"result": {
        "sane_defaults": {}, "types": sorted(feeds.MISP_TYPES), "categories": ["Network activity"],
        "category_type_mappings": {"Network activity": sorted(feeds.MISP_TYPES)}}})


def test_misp_server_connector_with_real_pymisp_against_rest_fixture():
    """Real PyMISP over mocked HTTP (MISP REST API shapes): to_ids only, matchable types,
    incremental timestamp, event tags included; the result is tenant-private intel."""
    with responses.RequestsMock() as rsps:
        _mock_misp_init(rsps)
        rsps.add(responses.POST, f"{MISP_URL}/attributes/restSearch", json=json.loads(fixture("misp_server_restsearch.json")))
        obs, cursor = misp_server.fetch(MISP_URL, "test-key", since=1793400000, page_size=1000)
        body = json.loads(rsps.calls[-1].request.body)
        assert rsps.calls[-1].request.headers["Authorization"] == "test-key"
    assert body["to_ids"] == 1 and body["timestamp"] == 1793400000 and body["includeEventTags"] == 1
    assert set(body["type"]) == set(feeds.MISP_TYPES) and body["limit"] == 1000 and body["page"] == 1
    assert cursor == "1793500100"
    got = {(o.type_hint, o.value): o for o in obs}
    assert got[("ipv4", "45.33.32.210")].tlp == "red" and got[("domain", "internal-c2.example")].tlp == "amber"
    assert got[("ipv4", "45.33.32.210")].source_info == "Tenant case 42"
    assert got[("ipv4", "45.33.32.210")].reference_url == f"{MISP_URL}/events/view/17"
    rows, counts = store.prepare_rows(obs, "tenant-a", NOW)
    assert len(rows) == 2 and not counts["rejected"]                               # private to tenant-a
    _, counts = store.prepare_rows(obs, None, NOW)
    assert sum(counts["rejected"].values()) == 2                                   # could never become global


def test_misp_server_errors_are_feed_failures():
    with responses.RequestsMock() as rsps:
        _mock_misp_init(rsps)
        rsps.add(responses.POST, f"{MISP_URL}/attributes/restSearch", status=403, json={"message": "Authentication failed."})
        with pytest.raises(FeedError):
            misp_server.fetch(MISP_URL, "bad-key")
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, f"{MISP_URL}/servers/getPyMISPVersion.json", body=ConnectionError("refused"))
        with pytest.raises(FeedError):
            misp_server.fetch(MISP_URL, "k")


def test_allowlist_check_handles_ipv6_ranges():
    """6.2 regression: Spamhaus DROP v6 brought cidr6 IOCs; Allow.blocks raised KeyError."""
    from shadowtracer_intel import listgen
    allow = listgen.Allow([("ipv6", "2001:4860:4860::8888"), ("ipv4", "8.8.8.8")])
    assert allow.blocks("cidr6", "2001:4860::/32") and not allow.blocks("cidr6", "2a10:cc40::/29")
    assert not allow.blocks("cidr4", "45.0.0.0/11") and allow.blocks("cidr4", "8.8.0.0/16")
