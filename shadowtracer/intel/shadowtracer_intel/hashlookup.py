"""CIRCL hashlookup (Phase 6.5 A1): bulk-check FIM file hashes against hashlookup.circl.lu, a
database of KNOWN files (NSRL and others). A hash that is present and not flagged malicious is a
known-good file: the incident shows "known file (source: …)", its priority is lowered, and no TI
alert fires. Nothing but the hash leaves the host.

Licence CC-BY (verified 2026-11-11, docs/design/LICENSE_INVENTORY.md §3): commercial use is
allowed; the only acknowledgement required is a reference to the hashlookup page, which is why
ATTRIBUTION travels with every known-good verdict. Bulk endpoints take {"hashes": [...]} and
return one record per hash they know; unknown hashes are simply absent from the response.
"""
import datetime as dt
import json
import urllib.error
import urllib.request

from sqlalchemy import text

BULK_SHA1 = "https://hashlookup.circl.lu/bulk/sha1"
BULK_MD5 = "https://hashlookup.circl.lu/bulk/md5"
ATTRIBUTION = "CIRCL hashlookup (https://www.circl.lu/services/hashlookup/)"
TTL = dt.timedelta(days=30)          # public known-file data changes slowly; cache ~30 days
MAX_BULK = 1000                      # hashes per request (fair use: one bulk call, not per-hash)
TRUST_FLOOR = 50                     # hashlookup:trust is 0..100; below this we do not call it known-good


class HashlookupError(Exception):
    pass


def _http_post(url: str, payload: dict, timeout: float = 30, http=None) -> tuple:
    if http is not None:
        return http(url, payload, timeout)
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": "shadowtracer-ti-sync", "Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def source_label(rec: dict) -> str:
    """Human attribution for the known-file match: NSRL/RDS when present, else the raw source/db."""
    db = (rec.get("db") or rec.get("source") or "").strip()
    if "nsrl" in db.lower() or str(rec.get("source", "")).upper().startswith("RDS") or rec.get("RDS:package_id"):
        return "NSRL"
    return db or "hashlookup"


def is_known_good(rec: dict) -> bool:
    """Present in a known-file DB and not flagged malicious / low-trust."""
    if str(rec.get("KnownMalicious", "")).strip().lower() in ("true", "1", "yes"):
        return False
    trust = rec.get("hashlookup:trust")
    if trust is not None:
        try:
            return int(trust) >= TRUST_FLOOR
        except (TypeError, ValueError):
            pass
    return True                      # in a known-file DB with no trust/malicious signal: known file


def parse(records) -> dict:
    """CIRCL bulk response (a list of records) -> {HASH_UPPER: {known_good, source, filename}}."""
    out = {}
    for rec in records if isinstance(records, list) else []:
        h = (rec.get("SHA-1") or rec.get("MD5") or "").upper()
        if not h:
            continue
        out[h] = {"known_good": is_known_good(rec), "source": source_label(rec),
                  "filename": rec.get("FileName") or ""}
    return out


def bulk_lookup(hashes, which: str = "sha1", http=None, now: dt.datetime = None) -> dict:
    """Look up up to MAX_BULK hashes in one bulk call. -> {HASH_UPPER: verdict dict} for the hashes
    the service KNOWS (unknown hashes are absent, which the caller reads as "not known-good")."""
    hashes = [h.upper() for h in hashes if h]
    if not hashes:
        return {}
    if len(hashes) > MAX_BULK:
        raise HashlookupError(f"bulk call capped at {MAX_BULK} hashes, got {len(hashes)}")
    url = BULK_SHA1 if which == "sha1" else BULK_MD5
    status, body = _http_post(url, {"hashes": hashes}, http=http)
    if status != 200:
        raise HashlookupError(f"HTTP {status}")
    try:
        records = json.loads(body)
    except ValueError as exc:
        raise HashlookupError(f"not JSON: {exc}") from exc
    return parse(records)


# ---------------------------------------------------------------- Postgres cache (global, ~30 days)
def cached(conn, shas, now: dt.datetime) -> dict:
    """Non-expired cache rows for these sha256 values. -> {sha256: {known_good, source, filename}}."""
    if not shas:
        return {}
    rows = conn.execute(text("SELECT sha256, known_good, source, filename FROM hashlookup_verdicts "
                             "WHERE sha256 = ANY(:s) AND expires_at > :now"), {"s": list(shas), "now": now}).all()
    return {r[0]: {"known_good": r[1], "source": r[2], "filename": r[3]} for r in rows}


def store(conn, verdicts: dict, now: dt.datetime) -> None:
    """Upsert {sha256: {known_good, source, filename, lookup_hash}} with a fresh TTL."""
    for sha, v in verdicts.items():
        conn.execute(text(
            "INSERT INTO hashlookup_verdicts (sha256, known_good, source, filename, lookup_hash, checked_at, expires_at) "
            "VALUES (:s, :kg, :src, :fn, :lh, :now, :exp) ON CONFLICT (sha256) DO UPDATE SET "
            "known_good = EXCLUDED.known_good, source = EXCLUDED.source, filename = EXCLUDED.filename, "
            "lookup_hash = EXCLUDED.lookup_hash, checked_at = EXCLUDED.checked_at, expires_at = EXCLUDED.expires_at"),
            {"s": sha, "kg": v["known_good"], "src": v.get("source"), "fn": v.get("filename"),
             "lh": v.get("lookup_hash"), "now": now, "exp": now + TTL})


def resolve(conn, requests: list, now: dt.datetime, http=None) -> dict:
    """requests: dicts with sha256 and optional sha1/md5 (from vt_requests). Returns
    {sha256: {known_good, source, filename}} using the global cache first, then ONE bulk CIRCL call
    for the uncached (by sha1, falling back to md5). New verdicts are cached. A hash CIRCL does not
    know is cached as not-known-good (unknown file), so we do not re-query it every cycle."""
    by_sha = {r["sha256"]: r for r in requests if r.get("sha256")}
    out = cached(conn, list(by_sha), now)
    todo = {s: r for s, r in by_sha.items() if s not in out}
    if not todo:
        return out
    # group the uncached by which hash we will query CIRCL with
    sha1_map = {r["sha1"].upper(): s for s, r in todo.items() if r.get("sha1")}
    md5_map = {r["md5"].upper(): s for s, r in todo.items() if not r.get("sha1") and r.get("md5")}
    found = {}
    for which, m in (("sha1", sha1_map), ("md5", md5_map)):
        for i in range(0, len(m), MAX_BULK):
            batch = list(m)[i:i + MAX_BULK]
            for h, v in bulk_lookup(batch, which=which, http=http).items():
                if h in m:
                    found[m[h]] = {**v, "lookup_hash": h}
    verdicts = {}
    for sha, r in todo.items():
        v = found.get(sha) or {"known_good": False, "source": None, "filename": None,
                               "lookup_hash": (r.get("sha1") or r.get("md5") or "").upper() or None}
        verdicts[sha] = v
        out[sha] = {"known_good": v["known_good"], "source": v.get("source"), "filename": v.get("filename")}
    store(conn, verdicts, now)
    return out
