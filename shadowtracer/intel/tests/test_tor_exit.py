"""Tor exit list parsing (Phase 6.5 A4)."""
from shadowtracer_intel import tor_exit


def test_parse_keeps_valid_ips_ignores_junk():
    raw = b"# header comment\n171.25.193.25\n80.67.167.81\n\n2001:db8::1\nnot-an-ip\n10.0.0.999\n"
    ips = tor_exit.parse(raw)
    assert ips == ["171.25.193.25", "80.67.167.81", "2001:db8::1"]


def test_parse_normalises_ipv6():
    assert tor_exit.parse(b"2001:0db8:0000::0001\n") == ["2001:db8::1"]


def test_attribution_is_cc0_tor():
    assert "tor" in tor_exit.ATTRIBUTION.lower() and "CC0" in tor_exit.ATTRIBUTION
