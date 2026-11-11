"""Tor exit node context feed (Phase 6.5 A4). The Tor Project's bulk exit list (CC0, verified
2026-11-11) is refreshed by ti-sync into tor_exit_nodes; a tagging pass then sets
incidents.tor_exit_ips = the subset of an incident's source IPs that are Tor exit nodes. This is
**context only**: a low-severity "Tor exit" tag shown to analysts, never an alert on its own, and
it never changes an incident's priority.
"""
import datetime as dt
import ipaddress

from sqlalchemy import text

URL = "https://check.torproject.org/torbulkexitlist"
ATTRIBUTION = "Tor Project exit list (CC0, check.torproject.org)"
STALE_DAYS = 3          # an IP absent from the list this long is no longer an exit node
TAG_WINDOW = dt.timedelta(days=7)


def parse(raw: bytes) -> list:
    """One IP per line (comments/blank lines ignored); only valid IPv4/IPv6 kept."""
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return out


def refresh(conn, ips: list, now: dt.datetime = None, stale_days: int = STALE_DAYS) -> dict:
    """Upsert the current exit list and drop nodes that have been absent for stale_days."""
    now = now or dt.datetime.now(dt.timezone.utc)
    for ip in ips:
        conn.execute(text("INSERT INTO tor_exit_nodes (ip, first_seen, last_seen) VALUES (:ip, :now, :now) "
                          "ON CONFLICT (ip) DO UPDATE SET last_seen = :now"), {"ip": ip, "now": now})
    pruned = conn.execute(text("DELETE FROM tor_exit_nodes WHERE last_seen < :cut"),
                          {"cut": now - dt.timedelta(days=stale_days)}).rowcount
    return {"nodes": len(ips), "pruned": pruned}


def tag_incidents(conn, window: dt.timedelta = TAG_WINDOW, now: dt.datetime = None) -> int:
    """Set tor_exit_ips on recent incidents whose source IPs include a Tor exit node (context only)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    # cast to varchar[] to match incidents.tor_exit_ips (tor_exit_nodes.ip is text)
    match = "ARRAY(SELECT n.ip::varchar FROM tor_exit_nodes n WHERE n.ip = ANY(i.source_ips))"
    return conn.execute(text(
        f"UPDATE incidents i SET tor_exit_ips = {match} "
        f"WHERE i.last_seen > :since AND i.tor_exit_ips IS DISTINCT FROM {match}"),
        {"since": now - window}).rowcount
