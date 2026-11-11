"""Where a file lives, and whether its name is a known dual-use tool (Phase 6.5). Shared by the
free CIRCL hashlookup layer (A1) and the selective VirusTotal funnel (C): a known-good verdict may
lower an incident's priority ONLY for an expected install location with a non-dual-use name. A
known-good file in a high-risk path (temp, web roots, cron/systemd/startup, home downloads) keeps
its priority and is labelled "known file in unusual location"; a dual-use tool is never down-ranked.
All three lists are configurable by env (comma-separated).
"""
import os


def _list(env_var: str, default: tuple) -> tuple:
    v = os.environ.get(env_var)
    return tuple(p.strip().lower() for p in v.split(",") if p.strip()) if v else default


# Expected install locations: a known-good file here is routine OS/package content.
EXPECTED_PATHS = _list("ST_EXPECTED_PATHS", (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
    "/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/", "/usr/share/", "/opt/"))

# High-risk locations: a file here (even a known-good one) is suspicious by placement.
HIGH_RISK_PATHS = _list("ST_HIGH_RISK_PATHS", (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/var/www/", "/srv/www/", "/usr/share/nginx/html/",
    "/etc/cron", "/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/", "/etc/init.d/", "/etc/rc",
    "/root/downloads/", "/root/.config/autostart/"))

# Dual-use tools: appearance is never down-ranked by a known-good verdict (basename match).
DUAL_USE_TOOLS = frozenset(_list("ST_DUAL_USE_TOOLS", (
    "nc", "ncat", "netcat", "nmap", "socat", "chisel", "cryptcat", "powercat", "psexec", "plink",
    "proxychains", "frpc", "frps", "gost", "iodine", "dnscat2", "ngrok", "sliver", "merlin")))


def is_dual_use(path: str) -> bool:
    return os.path.basename(path or "").lower() in DUAL_USE_TOOLS


def _is_home_download(p: str) -> bool:
    parts = p.split("/")
    return len(parts) >= 4 and parts[1] == "home" and parts[3] == "downloads"


def classify(path: str) -> str:
    """-> 'expected' | 'high_risk' | 'other'. High-risk is checked first, so /usr/lib/systemd/ (a
    startup location under an otherwise expected prefix) is high-risk, not expected."""
    p = (path or "").lower()
    if not p.startswith("/"):
        return "other"
    if any(p.startswith(h) for h in HIGH_RISK_PATHS) or _is_home_download(p):
        return "high_risk"
    if any(p.startswith(e) for e in EXPECTED_PATHS):
        return "expected"
    return "other"


def known_good_outcome(path: str) -> tuple:
    """A known-good file's effect. -> (downrank: bool, note: str)."""
    if is_dual_use(path):
        return False, "known dual-use tool"
    c = classify(path)
    if c == "expected":
        return True, "known file"
    if c == "high_risk":
        return False, "known file in unusual location"
    return False, "known file (location not whitelisted)"
