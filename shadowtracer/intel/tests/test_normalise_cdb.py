"""Normalisation rejects (never escapes) anything that could break a CDB list
(THREAT_INTEL.md §4.6-4.7), and the list writer proves the file parses back exactly."""
import pytest

from shadowtracer_intel import cdb, normalise as n
from shadowtracer_intel.normalise import Rejected

# Every crafted value from THREAT_INTEL.md §4.7, plus a few more.
CRAFTED = [
    ("domain", "evil.com\n10.:"),        # newline -> a second entry (a /8 prefix)
    ("domain", "evil.com\r\n10.:"),
    ("domain", 'evil".com'),             # unbalanced quote -> entry silently skipped
    ("domain", "evil.com\x00x"),         # NUL -> truncated key
    ("domain", "ev il.com"),
    ("url", 'http://a.example/"x'),
    ("url", "http://a.example/x\ny:"),
    ("ipv4", "1.2.3.4\n10.:"),
    ("ipv4", ":"),
    ("md5", "d41d8cd98f00b204e9800998ecf8427" + "\n"),
    ("domain", "a" * 3000),
]


@pytest.mark.parametrize("typ,raw", CRAFTED)
def test_crafted_values_are_rejected_not_escaped(typ, raw):
    with pytest.raises(Rejected):
        n.normalise(typ, raw)


def test_refang_and_canonical_forms():
    assert n.normalise("ipv4", "45[.]33[.]32[.]156") == ("ipv4", "45.33.32.156")
    assert n.normalise("url", "hxxps://Bad[.]Example:443/a?b=1#frag") == ("url", "https://bad.example/a?b=1")
    assert n.normalise("domain", "Bücher.Example.") == ("domain", "xn--bcher-kva.example")
    assert n.normalise("ipv6", "2001:4860:4860:0000:0000:0000:0000:8888") == ("ipv6", "2001:4860:4860::8888")
    assert n.normalise("ipv6", "::ffff:45.33.32.156") == ("ipv4", "45.33.32.156")
    assert n.normalise("cidr4", "45.33.32.7/24") == ("cidr4", "45.33.32.0/24")
    assert n.normalise("sha256", "A" * 64) == ("sha256", "a" * 64)


def test_ranges_and_special_addresses():
    for raw in ("10.1.2.3", "127.0.0.1", "192.168.1.1", "100.64.0.5", "169.254.1.1", "224.0.0.1", "198.51.100.7", "::1"):
        with pytest.raises(Rejected):
            n.normalise("ipv4" if "." in raw else "ipv6", raw)            # never in GLOBAL intel
    assert n.normalise("ipv4", "10.1.2.3", scope="tenant") == ("ipv4", "10.1.2.3")   # tenant-private may name its own hosts
    for raw in ("010.1.1.1", "45.0.0.0/8", "2001:db8::/16", "*.evil.example"):
        with pytest.raises(Rejected):
            n.normalise("domain" if raw.startswith("*") else "ipv4", raw)
    with pytest.raises(Rejected):
        n.normalise("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")  # empty file


def test_list_writer_round_trips_and_quotes_colons():
    keys = ["45.33.32.156", "45.33.32.", "2001:4860:4860::8888", "https://bad.example/a?b=1", "bad.example"]
    data = cdb.write(keys)
    assert sorted(cdb.parse(data)) == sorted(keys)
    assert b'"2001:4860:4860::8888":\n' in data and b'"https://bad.example/a?b=1":\n' in data


@pytest.mark.parametrize("bad", ["evil.com\n10.", 'a"b', "x\x00", ""])
def test_list_writer_refuses_a_key_that_would_change_the_list(bad):
    with pytest.raises(cdb.UnsafeList):
        cdb.write(["45.33.32.156", bad])


def test_parser_mirrors_lists_make_c():
    # what analysisd would do with raw crafted lines - the reason the writer must refuse them
    assert cdb.parse(b"evil.com\n10.:\n") == ["10."]                 # first line has no ':' -> skipped; second adds a /8
    assert cdb.parse(b'"unbalanced:x\n') == []                        # quote never closed -> skipped
    assert cdb.parse(b"2001:db8::1:\n") == ["2001"]                   # unquoted IPv6 -> key cut at the first ':'
