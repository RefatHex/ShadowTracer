"""CIRCL hashlookup client (Phase 6.5 A1): known-good detection, attribution, bulk request."""
import json

import pytest

from shadowtracer_intel import hashlookup


def test_parse_marks_present_hash_known_good_with_source():
    recs = [{"SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "FileName": "cmd.exe",
             "RDS:package_id": "1", "source": "RDS", "db": "nsrl"}]
    out = hashlookup.parse(recs)
    v = out["DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"]
    assert v["known_good"] is True and v["source"] == "NSRL" and v["filename"] == "cmd.exe"


def test_known_malicious_or_low_trust_is_not_known_good():
    assert hashlookup.is_known_good({"SHA-1": "x", "KnownMalicious": "true"}) is False
    assert hashlookup.is_known_good({"SHA-1": "x", "hashlookup:trust": 10}) is False
    assert hashlookup.is_known_good({"SHA-1": "x", "hashlookup:trust": 80}) is True
    assert hashlookup.is_known_good({"SHA-1": "x", "db": "snap:abc"}) is True   # known file, no trust/malicious


def test_unknown_hash_is_absent_from_the_response():
    # CIRCL omits hashes it does not know; the caller reads absence as "not known-good"
    out = hashlookup.parse([{"SHA-1": "aaaa", "db": "nsrl"}])
    assert "BBBB" not in out and "AAAA" in out


def test_bulk_lookup_posts_hashes_and_parses(monkeypatch):
    calls = {}

    def fake_http(url, payload, timeout):
        calls["url"], calls["payload"] = url, payload
        return 200, json.dumps([{"SHA-1": payload["hashes"][0], "db": "nsrl", "source": "RDS", "RDS:package_id": "1"}]).encode()

    out = hashlookup.bulk_lookup(["abc123", "def456"], which="sha1", http=fake_http)
    assert calls["url"] == hashlookup.BULK_SHA1 and calls["payload"]["hashes"] == ["ABC123", "DEF456"]
    assert out["ABC123"]["known_good"] and out["ABC123"]["source"] == "NSRL"


def test_bulk_lookup_caps_batch_and_raises_on_http_error():
    with pytest.raises(hashlookup.HashlookupError):
        hashlookup.bulk_lookup(["x"] * (hashlookup.MAX_BULK + 1))
    with pytest.raises(hashlookup.HashlookupError):
        hashlookup.bulk_lookup(["x"], http=lambda *a: (503, b"down"))


def test_attribution_is_the_ccby_reference():
    assert "circl.lu/services/hashlookup" in hashlookup.ATTRIBUTION
