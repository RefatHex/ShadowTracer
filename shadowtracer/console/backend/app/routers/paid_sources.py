"""Phase 6.5 B: tenant-managed paid threat-intel sources (THREAT_INTEL.md §10 B).

A tenant supplies its own API key for a paid source (VirusTotal, MalwareBazaar, AbuseIPDB,
GreyNoise). The key is sealed with envelope encryption (secrets_crypto) under the deployment
KEK and stored write-only: this API never returns the key, only a non-secret fingerprint and
last-4 so an admin can confirm which key is set. The intel worker reads the sealed key to make
the outbound call; the backend never calls these services and never holds a plaintext key.

Opt-in per source (enabled), with per-tenant daily_budget and cache_ttl overrides. Every change
is written to the hash-chained audit log (the key value is never audited or logged).
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import secrets_crypto
from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ADMIN_ONLY, ALL_ROLES, CurrentUser

router = APIRouter(prefix="/api/ti/paid-sources", tags=["threat-intel"])

# source -> (display name, default daily budget, default cache TTL hours). These defaults apply
# when the tenant leaves daily_budget / cache_ttl_hours NULL.
SOURCES = {
    "virustotal":    ("VirusTotal",    500, 24),
    "malwarebazaar": ("MalwareBazaar", 1000, 24),
    "abuseipdb":     ("AbuseIPDB",     1000, 12),
    "greynoise":     ("GreyNoise",     1000, 12),
}


class SourceStatus(BaseModel):
    source: str
    display_name: str
    enabled: bool
    has_key: bool
    key_fingerprint: str | None
    key_last4: str | None
    key_version: int
    daily_budget: int            # effective (override or source default)
    cache_ttl_hours: int         # effective
    daily_budget_default: int
    cache_ttl_hours_default: int
    cooldown_until: str | None
    rotated_at: str | None
    updated_at: str | None


class PutSource(BaseModel):
    # the key is write-only: supplied to set/rotate, never returned. Omit to change only settings.
    key: str | None = Field(default=None, min_length=8, max_length=512)
    enabled: bool = False
    daily_budget: int | None = Field(default=None, ge=0, le=10_000_000)
    cache_ttl_hours: int | None = Field(default=None, ge=0, le=24 * 365)


def _check_source(source: str) -> None:
    if source not in SOURCES:
        raise HTTPException(status_code=404, detail=f"unknown source; one of: {', '.join(sorted(SOURCES))}")


def _iso(v):
    return v.isoformat() if v is not None else None


def _status_row(source: str, row) -> SourceStatus:
    display, def_budget, def_ttl = SOURCES[source]
    r = row or {}
    return SourceStatus(
        source=source, display_name=display,
        enabled=bool(r.get("enabled", False)),
        has_key=bool(r.get("sealed_key")),
        key_fingerprint=r.get("key_fingerprint"),
        key_last4=r.get("key_last4"),
        key_version=r.get("key_version", 0) or 0,
        daily_budget=r["daily_budget"] if r.get("daily_budget") is not None else def_budget,
        cache_ttl_hours=r["cache_ttl_hours"] if r.get("cache_ttl_hours") is not None else def_ttl,
        daily_budget_default=def_budget, cache_ttl_hours_default=def_ttl,
        cooldown_until=_iso(r.get("cooldown_until")), rotated_at=_iso(r.get("rotated_at")),
        updated_at=_iso(r.get("updated_at")),
    )


# never SELECT sealed_key here - the console must not read key material back
_META_COLS = ("source, enabled, (sealed_key IS NOT NULL) AS sealed_key, key_fingerprint, key_last4, "
              "key_version, daily_budget, cache_ttl_hours, cooldown_until, rotated_at, updated_at")


@router.get("", response_model=list[SourceStatus])
def list_sources(db: Session = Depends(get_db), current_user: CurrentUser = Depends(ALL_ROLES)):
    rows = {r["source"]: dict(r) for r in db.execute(
        text(f"SELECT {_META_COLS} FROM tenant_source_keys WHERE tenant_key = :t"),
        {"t": current_user.tenant_key}).mappings()}
    return [_status_row(s, rows.get(s)) for s in SOURCES]


@router.put("/{source}", response_model=SourceStatus)
def put_source(source: str, body: PutSource, db: Session = Depends(get_db),
               settings: Settings = Depends(get_settings), current_user: CurrentUser = Depends(ADMIN_ONLY)):
    """Set or rotate the tenant's key for one source and/or its opt-in and budgets. Supplying
    `key` seals it (rotation bumps key_version); omitting it changes only the settings. Enabling
    a source requires a key to be present. The key value is never logged or returned."""
    _check_source(source)
    tenant = current_user.tenant_key

    existing = db.execute(text(
        "SELECT (sealed_key IS NOT NULL) AS has_key, key_version FROM tenant_source_keys "
        "WHERE tenant_key = :t AND source = :s"), {"t": tenant, "s": source}).mappings().first()
    has_key = bool(existing and existing["has_key"])

    audit_detail = f"source={source}"
    if body.key is not None:
        if settings.key_encryption_key is None:
            raise HTTPException(status_code=503, detail="paid-key management is not configured (no KEY_ENCRYPTION_KEY)")
        key = body.key.strip()
        if not key:
            raise HTTPException(status_code=422, detail="key must not be blank")
        sealed = secrets_crypto.seal(settings.key_encryption_key, tenant, source, key)
        fp, l4 = secrets_crypto.fingerprint(key), secrets_crypto.last4(key)
        db.execute(text(
            "INSERT INTO tenant_source_keys (tenant_key, source, enabled, sealed_key, key_fingerprint, key_last4, "
            "  key_version, daily_budget, cache_ttl_hours, created_by, created_at, updated_at, rotated_at) "
            "VALUES (:t, :s, :e, :sk, :fp, :l4, 1, :b, :c, :u, now(), now(), now()) "
            "ON CONFLICT (tenant_key, source) DO UPDATE SET enabled = EXCLUDED.enabled, sealed_key = EXCLUDED.sealed_key, "
            "  key_fingerprint = EXCLUDED.key_fingerprint, key_last4 = EXCLUDED.key_last4, "
            "  key_version = tenant_source_keys.key_version + 1, daily_budget = EXCLUDED.daily_budget, "
            "  cache_ttl_hours = EXCLUDED.cache_ttl_hours, updated_at = now(), rotated_at = now(), "
            "  cooldown_until = NULL, created_by = EXCLUDED.created_by"),
            {"t": tenant, "s": source, "e": body.enabled, "sk": sealed, "fp": fp, "l4": l4,
             "b": body.daily_budget, "c": body.cache_ttl_hours, "u": str(current_user.user_id)})
        action = "paid_source_key_rotated" if has_key else "paid_source_key_set"
        audit_detail += f",fingerprint={fp},last4={l4},enabled={body.enabled}"
    else:
        # settings-only change; cannot enable without a key on file
        if body.enabled and not has_key:
            raise HTTPException(status_code=409, detail=f"no key on file for {source}; set a key before enabling it")
        updated = db.execute(text(
            "UPDATE tenant_source_keys SET enabled = :e, daily_budget = :b, cache_ttl_hours = :c, updated_at = now() "
            "WHERE tenant_key = :t AND source = :s"),
            {"t": tenant, "s": source, "e": body.enabled, "b": body.daily_budget, "c": body.cache_ttl_hours})
        if updated.rowcount == 0:
            # no row yet and no key supplied: only valid when not enabling (records the settings intent)
            db.execute(text(
                "INSERT INTO tenant_source_keys (tenant_key, source, enabled, daily_budget, cache_ttl_hours, "
                "  created_by, created_at, updated_at) VALUES (:t, :s, false, :b, :c, :u, now(), now())"),
                {"t": tenant, "s": source, "b": body.daily_budget, "c": body.cache_ttl_hours, "u": str(current_user.user_id)})
        action = "paid_source_settings_changed"
        audit_detail += f",enabled={body.enabled},daily_budget={body.daily_budget},cache_ttl_hours={body.cache_ttl_hours}"

    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
                 action=action, target=audit_detail, outcome="success")
    row = db.execute(text(f"SELECT {_META_COLS} FROM tenant_source_keys WHERE tenant_key = :t AND source = :s"),
                     {"t": tenant, "s": source}).mappings().first()
    return _status_row(source, dict(row))


@router.post("/{source}/remove", response_model=SourceStatus)
def remove_source_key(source: str, db: Session = Depends(get_db), current_user: CurrentUser = Depends(ADMIN_ONLY)):
    """Remove the tenant's key for a source and disable it (POST, not DELETE: the app's CORS
    allows GET/POST/PATCH/PUT only). Keeps the row (with its settings)
    so the tenant's budget/cache choices survive a key removal; the key material is wiped."""
    _check_source(source)
    tenant = current_user.tenant_key
    res = db.execute(text(
        "UPDATE tenant_source_keys SET sealed_key = NULL, key_fingerprint = NULL, key_last4 = NULL, "
        "enabled = false, rotated_at = NULL, cooldown_until = NULL, updated_at = now() "
        "WHERE tenant_key = :t AND source = :s AND sealed_key IS NOT NULL"), {"t": tenant, "s": source})
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail=f"no key on file for {source}")
    append_entry(db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
                 action="paid_source_key_removed", target=f"source={source}", outcome="success")
    row = db.execute(text(f"SELECT {_META_COLS} FROM tenant_source_keys WHERE tenant_key = :t AND source = :s"),
                     {"t": tenant, "s": source}).mappings().first()
    return _status_row(source, dict(row) if row else None)
