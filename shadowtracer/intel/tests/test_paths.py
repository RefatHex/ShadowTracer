"""Path classification + known-good outcome (Phase 6.5 A1 gap fix)."""
from shadowtracer_intel import paths


def test_expected_install_locations_are_downranked():
    for p in ("/usr/bin/ls", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/bin/cat", "/opt/app/tool"):
        assert paths.classify(p) == "expected"
        assert paths.known_good_outcome(p) == (True, "known file")


def test_high_risk_locations_keep_priority_and_get_unusual_label():
    for p in ("/tmp/ls", "/var/tmp/x", "/dev/shm/y", "/var/www/html/shell", "/etc/cron.d/job",
              "/etc/systemd/system/eye.service", "/usr/lib/systemd/system/x.service", "/home/alice/Downloads/ls"):
        assert paths.classify(p) == "high_risk"
        assert paths.known_good_outcome(p) == (False, "known file in unusual location")


def test_dual_use_tools_are_never_downranked_even_in_expected_paths():
    assert paths.is_dual_use("/usr/bin/nc") and paths.is_dual_use("/usr/local/bin/socat")
    assert paths.known_good_outcome("/usr/bin/nmap") == (False, "known dual-use tool")
    assert paths.known_good_outcome("/tmp/ncat") == (False, "known dual-use tool")   # dual-use wins over location


def test_unwhitelisted_location_keeps_priority():
    assert paths.classify("/data/custom/tool") == "other"
    assert paths.known_good_outcome("/data/custom/tool") == (False, "known file (location not whitelisted)")


def test_env_override(monkeypatch):
    monkeypatch.setenv("ST_DUAL_USE_TOOLS", "weirdtool")
    import importlib
    importlib.reload(paths)
    try:
        assert paths.is_dual_use("/usr/bin/weirdtool") and not paths.is_dual_use("/usr/bin/nc")
    finally:
        monkeypatch.delenv("ST_DUAL_USE_TOOLS")
        importlib.reload(paths)
