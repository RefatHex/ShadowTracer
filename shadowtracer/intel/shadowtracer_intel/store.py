"""IOC store access (Postgres, ingest migration 14998d8588fb). THREAT_INTEL.md §4.1.

One iocs row per observable per tenant scope; one ioc_sightings row per (ioc, source).
A sync applies a source's observations in ONE transaction: a failure or a held sync
changes nothing (§4.12).
"""
import datetime as dt
import json
import uuid
from dataclasses import dataclass

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


def stix_indicator_id(tenant_key, typ: str, value: str) -> str:
    return f"indicator--{uuid.uuid5(STIX_NS, f'{tenant_key or ''}|{typ}|{value}')}"


TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")
NEVER_GLOBAL_TLP = {"amber", "amber+strict", "red"}     # 6.2: never global, never leaves its tenant


@dataclass(slots=True)
class Row:
    """One (type, value) per sync, compact: lists of 10^5 entries are normal (6.2)."""
    typ: str
    value: str
    tlp: str
    labels: object                  # the observation's own tuple/list until a merge makes it a set
    mitre: object
    first_seen: dt.datetime
    last_seen: dt.datetime
    valid_until: dt.datetime
    source_ref: str
    reference_url: str
    source_info: str
    source_confidence: float


def _merge(rows: dict, typ, value, o, first, last) -> None:
    """A feed may list a value several times (OTX pulses, MISP events). Keeps the widest
    time range, the most restrictive TLP, all labels, and the newest observation's reference."""
    r = rows.get((typ, value))
    if r is None:
        rows[(typ, value)] = Row(typ, value, o.tlp, o.labels, o.mitre, first, last, o.valid_until, o.source_ref,
                                 o.reference_url, o.source_info, o.source_confidence)
        return
    r.labels = set(r.labels) | set(o.labels)
    r.mitre = set(r.mitre) | set(o.mitre)
    r.first_seen = min(r.first_seen, first)
    if TLP_ORDER.index(o.tlp) > TLP_ORDER.index(r.tlp):
        r.tlp = o.tlp
    if o.source_confidence is not None and (r.source_confidence or 0) < o.source_confidence:
        r.source_confidence = o.source_confidence
    r.valid_until = None if r.valid_until is None or o.valid_until is None else max(r.valid_until, o.valid_until)
    if last >= r.last_seen:
        r.last_seen, r.source_ref, r.reference_url, r.source_info = last, o.source_ref, o.reference_url, o.source_info


def prepare_rows(observations: list, tenant_key, now: dt.datetime, min_prefix: dict = None) -> tuple:
    """Normalise, enforce the TLP rule, merge duplicates -> ({(type, value): row}, counts)."""
    scope = "tenant" if tenant_key else "global"
    counts = {"received": len(observations), "accepted": 0, "rejected": {}, "by_type": {}}
    rows = {}
    for o in observations:
        try:
            if tenant_key is None and o.tlp in NEVER_GLOBAL_TLP:
                raise Rejected(f"TLP:{o.tlp.upper()} is never global")
            typ, value = normalise(o.type_hint, o.value, scope, min_prefix)
        except Rejected as exc:
            counts["rejected"][str(exc)] = counts["rejected"].get(str(exc), 0) + 1
            continue
        first = o.first_seen or now
        _merge(rows, typ, value, o, first, max(o.last_seen or first, first))
    return rows, counts


def apply_observations(conn, source_id: int, tenant_key, observations: list, snapshot: bool,
                       now: dt.datetime = None, min_prefix: dict = None) -> dict:
    """Normalise and upsert, set-based: one statement per table whatever the feed size
    (a per-row upsert of a 126,000-entry list was ~250,000 statements and as many
    ti_store_version trigger runs per sync). snapshot=True: the feed is a full list, so
    sightings of this source that are no longer in it are revoked (guarded against
    truncated downloads). Raises FeedError (held) - the caller rolls the transaction back.
    Global intel marked TLP:AMBER/AMBER+STRICT/RED is rejected: it is never global."""
    from psycopg2.extras import execute_values
    now = now or dt.datetime.now(dt.timezone.utc)
    rows, counts = prepare_rows(observations, tenant_key, now, min_prefix)
    conn.execute(text(
        "CREATE TEMP TABLE IF NOT EXISTS st_obs (typ text, value text, stix_id text, pattern text, tlp text, labels text[], "
        "mitre text[], first_seen timestamptz, last_seen timestamptz, valid_until timestamptz, source_ref text, "
        "reference_url text, source_info text, source_confidence real, ioc_id bigint) ON COMMIT DROP"))
    conn.execute(text("TRUNCATE st_obs"))
    if rows:
        cur = conn.connection.dbapi_connection.cursor()
        execute_values(cur, "INSERT INTO st_obs VALUES %s", ((
            r.typ, r.value, stix_indicator_id(tenant_key, r.typ, r.value), f"[{STIX_PATTERN[r.typ]} = '{r.value}']",
            r.tlp, sorted(r.labels), sorted(r.mitre), r.first_seen, r.last_seen, r.valid_until, r.source_ref,
            r.reference_url, r.source_info, r.source_confidence, None) for r in rows.values()), page_size=2000)
        conn.execute(text("CREATE INDEX IF NOT EXISTS st_obs_key ON st_obs (typ, value)"))
        scope_sql = "i.tenant_key IS NULL" if tenant_key is None else "i.tenant_key = :t"
        conn.execute(text(
            "INSERT INTO iocs (stix_id, tenant_key, type, value, pattern, tlp, labels, mitre, valid_from, last_seen, valid_until) "
            "SELECT stix_id, :t, typ, value, pattern, tlp, labels, mitre, first_seen, last_seen, last_seen FROM st_obs "
            "ON CONFLICT (tenant_key, type, value) DO UPDATE SET "
            " last_seen = GREATEST(iocs.last_seen, EXCLUDED.last_seen), valid_from = LEAST(iocs.valid_from, EXCLUDED.valid_from), "
            " labels = ARRAY(SELECT DISTINCT unnest(iocs.labels || EXCLUDED.labels)), "
            " mitre = ARRAY(SELECT DISTINCT unnest(iocs.mitre || EXCLUDED.mitre)), revoked = false, modified = now() "
            "WHERE iocs.revoked OR iocs.last_seen < EXCLUDED.last_seen OR iocs.valid_from > EXCLUDED.valid_from "
            " OR NOT (EXCLUDED.labels <@ iocs.labels) OR NOT (EXCLUDED.mitre <@ iocs.mitre)"), {"t": tenant_key})
        conn.execute(text(f"UPDATE st_obs o SET ioc_id = i.id FROM iocs i WHERE {scope_sql} AND i.type = o.typ AND i.value = o.value"),
                     {"t": tenant_key})
        conn.execute(text(
            "INSERT INTO ioc_sightings (ioc_id, source_id, source_ref, reference_url, source_info, source_confidence, tlp, labels, "
            " mitre, first_seen, last_seen, valid_until) SELECT ioc_id, :s, source_ref, reference_url, source_info, source_confidence, "
            " tlp, labels, mitre, first_seen, last_seen, valid_until FROM st_obs "
            "ON CONFLICT (ioc_id, source_id) DO UPDATE SET source_ref = EXCLUDED.source_ref, reference_url = EXCLUDED.reference_url, "
            " source_info = EXCLUDED.source_info, source_confidence = EXCLUDED.source_confidence, tlp = EXCLUDED.tlp, "
            " labels = EXCLUDED.labels, mitre = EXCLUDED.mitre, first_seen = LEAST(ioc_sightings.first_seen, EXCLUDED.first_seen), "
            " last_seen = GREATEST(ioc_sightings.last_seen, EXCLUDED.last_seen), valid_until = EXCLUDED.valid_until, revoked_at = NULL"),
            {"s": source_id})
        for typ, n in conn.execute(text("SELECT typ, count(*) FROM st_obs GROUP BY typ")).all():
            counts["by_type"][typ] = n
    counts["accepted"] = len(rows)
    if snapshot:
        live = conn.execute(text("SELECT count(*) FROM ioc_sightings WHERE source_id = :s AND revoked_at IS NULL"),
                            {"s": source_id}).scalar_one()
        removed = live - len(rows)
        if live > 10 and removed > SHRINK_GUARD * live:
            raise FeedError(f"held: snapshot would remove {removed} of {live} live IOCs (> {SHRINK_GUARD:.0%})")
        conn.execute(text("UPDATE ioc_sightings s SET revoked_at = :now WHERE s.source_id = :s AND s.revoked_at IS NULL "
                          "AND NOT EXISTS (SELECT 1 FROM st_obs o WHERE o.ioc_id = s.ioc_id)"), {"now": now, "s": source_id})
        counts["revoked"] = removed
    conn.execute(text("UPDATE iocs SET revoked = NOT EXISTS (SELECT 1 FROM ioc_sightings s WHERE s.ioc_id = iocs.id "
                      "AND s.revoked_at IS NULL) WHERE id IN (SELECT ioc_id FROM ioc_sightings WHERE source_id = :s) "
                      "AND revoked <> NOT EXISTS (SELECT 1 FROM ioc_sightings s WHERE s.ioc_id = iocs.id AND s.revoked_at IS NULL)"),
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
    # Nodes no longer deployed (e.g. a compose profile turned off) drop out of health.
    if result.nodes:
        conn.execute(text("DELETE FROM ti_list_versions WHERE tenant_key = :t AND NOT (node = ANY(:n))"),
                     {"t": tenant_key, "n": [r.node for r in result.nodes]})
    for r in result.nodes:
        conn.execute(text("DELETE FROM ti_list_versions WHERE tenant_key = :t AND node = :n"), {"t": tenant_key, "n": r.node})
        for path, digest in (r.versions.items() or [("*", None)]):
            conn.execute(text(
                "INSERT INTO ti_list_versions (tenant_key, node, path, role, sha256, entries, result, detail, checked_at) "
                "VALUES (:t, :n, :p, :role, :sha, :e, :res, :d, now())"), {
                    "t": tenant_key, "n": r.node, "p": path, "role": r.role, "sha": digest,
                    "e": safe_reload.entries(bundle[path]) if path in bundle and digest == safe_reload.sha(bundle[path]) else None,
                    "res": r.result, "d": "\n".join(r.detail)[:4000]})
