"""Phase 5A Step 3: the attack fingerprint. Computed once, when an
incident closes (see closer.py) - a sha256 over the attack's SHAPE only,
never anything that identifies who was involved: no IP addresses,
usernames, ports, timestamps, or agent ids. Hashing those would turn
every new source into a new fingerprint and the library would never
actually learn a pattern repeats.
"""

import hashlib
import ipaddress
import json
import math

# Bump whenever the shape computed below changes - stored alongside the
# hash on the incident so a future analyst can tell which incidents were
# fingerprinted under an older definition of "shape".
RULESET_VERSION = "2026.1"

DURATION_BUCKETS = (
    (60, "under_1m"),
    (600, "1m_10m"),
    (3600, "10m_1h"),
    (4 * 3600, "1h_4h"),
)


def _actor_class(source_ips: list[str], internal_ranges: list[str]) -> str:
    """local: the incident never carried a source IP at all (e.g. a local
    account-creation event). Otherwise internal if every observed IP
    falls in a configured internal range, external if any one of them
    doesn't - an attack is only as "internal" as its least internal
    source."""
    if not source_ips:
        return "local"
    networks = []
    for r in internal_ranges:
        try:
            networks.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            continue
    for ip_str in source_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not any(ip in net for net in networks):
            return "external"
    return "internal"


def _volume_bucket(alert_count: int) -> int:
    return max(0, int(math.floor(math.log2(max(alert_count, 1)))))


def _duration_bucket(first_seen, last_seen) -> str:
    duration_seconds = (last_seen - first_seen).total_seconds()
    for threshold, label in DURATION_BUCKETS:
        if duration_seconds < threshold:
            return label
    return "over_4h"


def fingerprint_shape(
    rule_groups: list[str],
    mitre_ids: list[str],
    source_ips: list[str],
    alert_count: int,
    first_seen,
    last_seen,
    os_family: str | None,
    role_tag: str | None,
    internal_ranges: list[str],
) -> dict:
    """The exact shape that gets hashed - exposed separately from
    compute_fingerprint so tests can inspect it directly, not just the
    opaque hash."""
    return {
        "rule_groups": sorted(rule_groups),
        "mitre_ids": list(mitre_ids),  # order of first appearance - never sorted
        "actor_class": _actor_class(source_ips, internal_ranges),
        "target_class": f"{os_family or 'unknown'}:{role_tag or 'none'}",
        "volume_bucket": _volume_bucket(alert_count),
        "duration_bucket": _duration_bucket(first_seen, last_seen),
    }


def compute_fingerprint(
    rule_groups: list[str],
    mitre_ids: list[str],
    source_ips: list[str],
    alert_count: int,
    first_seen,
    last_seen,
    os_family: str | None,
    role_tag: str | None,
    internal_ranges: list[str],
) -> str:
    shape = fingerprint_shape(
        rule_groups, mitre_ids, source_ips, alert_count, first_seen, last_seen,
        os_family, role_tag, internal_ranges,
    )
    canonical = json.dumps(shape, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
