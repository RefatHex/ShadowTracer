"""IOC store access (Postgres, ingest migration 14998d8588fb). THREAT_INTEL.md §4.1.

One iocs row per observable per tenant scope; one ioc_sightings row per (ioc, source).
A sync applies a source's observations in ONE transaction: a failure or a held sync
changes nothing (§4.12).
"""
import datetime as dt
import json
import uuid

from sqlalchemy import text

from .feeds import FeedError
from .normalise import Rejected, normalise

STIX_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")        # uuid.NAMESPACE_URL
DEFAULT_TRUST = {"manual": 1.0, "feodo": 0.8, "sslbl": 0.8, "otx": 0.7, "misp_feed": 0.6}
SHRINK_GUARD = 0.30                    # a snapshot removing more than this is held, not applied
STIX_PATTERN = {"ipv4": "ipv4-addr:value", "cidr4": "ipv4-addr:value", "ipv6": "ipv6-addr:value",
                "cidr6": "ipv6-addr:value", "domain": "domain-name:value", "url": "url:value",
                "md5": "file:hashes.MD5", "sha1": "file:hashes.'SHA-1'", "sha256": "file:hashes.'SHA-256'"}


def ensure_source(conn, name: str, kind: str, tenant_key: str = None, trust: float = None,
                  default_tlp: str = "clear", enabled: bool = True) -> int:
    return conn.execute(text(
        "INSERT INTO ti_sources (name, kind, tenant_key, stix_identity, trust, default_tlp, enabled) "
        "VALUES (:n, :k, :t, :sid, :tr, :tlp, :en) ON CONFLICT (name) DO UPDATE SET enabled = EXCLUDED.enabled "
        "RETURNING id"), {"n": name, "k": kind, "t": tenant_key, "sid": f"identity--{uuid.uuid5(STIX_NS, 'st-source:' + name)}",
                          "tr": DEFAULT_TRUST.get(kind, 0.6) if trust is None else trust, "tlp": default_tlp,
                          "en": enabled}).scalar_one()


def record_attempt(conn, source_id: int, error: str = None, counts: dict = None, cursor: str = None) -> None:
    conn.execute(text(
        "UPDATE ti_sources SET last_attempt_at = now(), last_error = :e, "
        "last_success_at = CASE WHEN :e IS NULL THEN now() ELSE last_success_at END, "
        "last_counts = CASE WHEN :e IS NULL THEN CAST(:c AS jsonb) ELSE last_counts END, "
        "sync_cursor = COALESCE(:cur, sync_cursor) WHERE id = :id"),
        {"id": source_id, "e": error, "c": json.dumps(counts or {}), "cur": cursor})


def apply_observations(conn, source_id: int, tenant_key, observations: list, snapshot: bool,
                       now: dt.datetime = None) -> dict:
    """Normalise and upsert. snapshot=True: the feed is a full list, so sightings of this
    source that are no longer in it are revoked (guarded against truncated downloads).
    Raises FeedError (held) - the caller rolls the transaction back."""
    now = now or dt.datetime.now(dt.timezone.utc)
    scope = "tenant" if tenant_key else "global"
    counts = {"received": len(observations), "accepted": 0, "rejected": {}, "by_type": {}}
    seen = set()
    for o in observations:
        try:
            typ, value = normalise(o.type_hint, o.value, scope)
        except Rejected as exc:
            counts["rejected"][str(exc)] = counts["rejected"].get(str(exc), 0) + 1
            continue
        first = o.first_seen or now
        last = o.last_seen or first
        ioc_id = conn.execute(text(
            "INSERT INTO iocs (stix_id, tenant_key, type, value, pattern, tlp, labels, mitre, valid_from, last_seen, valid_until) "
            "VALUES (:sid, :t, :ty, :v, :pat, :tlp, :lab, :mit, :f, :l, :l) "
            "ON CONFLICT (tenant_key, type, value) DO UPDATE SET "
            " last_seen = GREATEST(iocs.last_seen, EXCLUDED.last_seen), valid_from = LEAST(iocs.valid_from, EXCLUDED.valid_from), "
            " labels = ARRAY(SELECT DISTINCT unnest(iocs.labels || EXCLUDED.labels)), "
            " mitre = ARRAY(SELECT DISTINCT unnest(iocs.mitre || EXCLUDED.mitre)), revoked = false, modified = now() "
            "RETURNING id"), {
                "sid": f"indicator--{uuid.uuid5(STIX_NS, f'{tenant_key or ''}|{typ}|{value}')}", "t": tenant_key,
                "ty": typ, "v": value, "pat": f"[{STIX_PATTERN[typ]} = '{value}']", "tlp": o.tlp,
                "lab": o.labels, "mit": o.mitre, "f": first, "l": last}).scalar_one()
        conn.execute(text(
            "INSERT INTO ioc_sightings (ioc_id, source_id, source_ref, reference_url, source_confidence, tlp, labels, mitre, "
            " first_seen, last_seen, valid_until) VALUES (:i, :s, :ref, :url, :c, :tlp, :lab, :mit, :f, :l, :vu) "
            "ON CONFLICT (ioc_id, source_id) DO UPDATE SET source_ref = EXCLUDED.source_ref, reference_url = EXCLUDED.reference_url, "
            " source_confidence = EXCLUDED.source_confidence, tlp = EXCLUDED.tlp, labels = EXCLUDED.labels, mitre = EXCLUDED.mitre, "
            " first_seen = LEAST(ioc_sightings.first_seen, EXCLUDED.first_seen), "
            " last_seen = GREATEST(ioc_sightings.last_seen, EXCLUDED.last_seen), valid_until = EXCLUDED.valid_until, revoked_at = NULL"),
            {"i": ioc_id, "s": source_id, "ref": o.source_ref, "url": o.reference_url, "c": o.source_confidence,
             "tlp": o.tlp, "lab": o.labels, "mit": o.mitre, "f": first, "l": last, "vu": o.valid_until})
        if ioc_id not in seen:
            seen.add(ioc_id)
            counts["by_type"][typ] = counts["by_type"].get(typ, 0) + 1
    counts["accepted"] = len(seen)
    if snapshot:
        live = conn.execute(text("SELECT count(*) FROM ioc_sightings WHERE source_id = :s AND revoked_at IS NULL"),
                            {"s": source_id}).scalar_one()
        removed = live - len(seen)
        if live > 10 and removed > SHRINK_GUARD * live:
            raise FeedError(f"held: snapshot would remove {removed} of {live} live IOCs (> {SHRINK_GUARD:.0%})")
        conn.execute(text("UPDATE ioc_sightings SET revoked_at = :now WHERE source_id = :s AND revoked_at IS NULL "
                          "AND NOT (ioc_id = ANY(:seen))"), {"now": now, "s": source_id, "seen": list(seen)})
        counts["revoked"] = removed
    conn.execute(text("UPDATE iocs SET revoked = NOT EXISTS (SELECT 1 FROM ioc_sightings s WHERE s.ioc_id = iocs.id "
                      "AND s.revoked_at IS NULL) WHERE id IN (SELECT ioc_id FROM ioc_sightings WHERE source_id = :s)"),
                 {"s": source_id})
    return counts


def replace_allowlist(conn, kind: str, origin_ref: str, entries: list, tenant_key: str = None,
                      reason: str = "", created_by: str = "ti-sync") -> int:
    """Replace every allowlist row of (kind, origin_ref, tenant) with these normalised
    (type, value) entries. Invalid entries are skipped."""
    conn.execute(text("DELETE FROM ti_allowlist WHERE kind = :k AND origin_ref = :o AND tenant_key IS NOT DISTINCT FROM :t"),
                 {"k": kind, "o": origin_ref, "t": tenant_key})
    n = 0
    for typ, value in entries:
        try:
            typ, value = normalise(typ, value, "tenant")
        except Rejected:
            continue
        conn.execute(text("INSERT INTO ti_allowlist (tenant_key, type, value, kind, reason, origin_ref, created_by) "
                          "VALUES (:t, :ty, :v, :k, :r, :o, :by) ON CONFLICT DO NOTHING"),
                     {"t": tenant_key, "ty": typ, "v": value, "k": kind, "r": reason or origin_ref, "o": origin_ref, "by": created_by})
        n += 1
    return n


def record_versions(conn, tenant_key: str, result, bundle: dict) -> None:
    """Every node's version of every TI file, for /health/detail (ti_list_versions)."""
    from . import safe_reload
    for r in result.nodes:
        conn.execute(text("DELETE FROM ti_list_versions WHERE tenant_key = :t AND node = :n"), {"t": tenant_key, "n": r.node})
        for path, digest in (r.versions.items() or [("*", None)]):
            conn.execute(text(
                "INSERT INTO ti_list_versions (tenant_key, node, path, role, sha256, entries, result, detail, checked_at) "
                "VALUES (:t, :n, :p, :role, :sha, :e, :res, :d, now())"), {
                    "t": tenant_key, "n": r.node, "p": path, "role": r.role, "sha": digest,
                    "e": safe_reload.entries(bundle[path]) if path in bundle and digest == safe_reload.sha(bundle[path]) else None,
                    "res": r.result, "d": "\n".join(r.detail)[:4000]})
