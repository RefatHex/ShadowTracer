"""Phase 6.5 C: analyst-initiated IP reputation lookups (AbuseIPDB, GreyNoise).

A button on an IP in the incident view calls this. The backend holds the KEK, so it opens the
tenant's own sealed key, calls the source once (synchronously), caches the verdict and audits it.
Same per-tenant key / opt-in / budget / cache / 429-cooldown as the automatic sources - but spent
only on a deliberate click, never a background worker (owner's 6.5 C constraint). analyst+ only.
"""
import datetime
import ipaddress
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import ip_sources, secrets_crypto
from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..rbac import ANALYST_OR_ABOVE, CurrentUser
from .paid_sources import SOURCES

router = APIRouter(prefix="/api/ti/ip-lookups", tags=["threat-intel"])
IP_SOURCES = ("abuseipdb", "greynoise")


class IPLookupRequest(BaseModel):
    ip: str
    source: str

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("not a valid IP address") from None


def _cache_get(db: Session, tenant: str, source: str, ip: str):
    r = db.execute(text("SELECT status, data, fetched_at FROM source_verdicts WHERE tenant_key=:t "
                        "AND source=:s AND indicator=:i AND expires_at > now()"),
                   {"t": tenant, "s": source, "i": ip}).mappings().first()
    return r


def _verdict_response(source, ip, status, data, fetched_at, served_from):
    return {"source": source, "ip": ip, "status": status, "data": data,
            "fetched_at": fetched_at.isoformat() if hasattr(fetched_at, "isoformat") else fetched_at,
            "served_from": served_from}


@router.post("")
def ip_lookup(body: IPLookupRequest, db: Session = Depends(get_db),
              settings: Settings = Depends(get_settings), current_user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    if body.source not in IP_SOURCES:
        raise HTTPException(status_code=404, detail=f"source must be one of: {', '.join(IP_SOURCES)}")
    tenant, source, ip = current_user.tenant_key, body.source, body.ip
    audit = lambda outcome: append_entry(  # noqa: E731
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action="ip_lookup", target=f"source={source},ip={ip}", outcome=outcome)

    cached = _cache_get(db, tenant, source, ip)
    if cached:
        audit("cached")
        return _verdict_response(source, ip, cached["status"], cached["data"], cached["fetched_at"], "cache")

    if settings.key_encryption_key is None:
        raise HTTPException(status_code=503, detail="paid-source lookups are not configured (no KEY_ENCRYPTION_KEY)")
    row = db.execute(text("SELECT enabled, sealed_key, daily_budget, cache_ttl_hours, cooldown_until "
                          "FROM tenant_source_keys WHERE tenant_key=:t AND source=:s"),
                     {"t": tenant, "s": source}).mappings().first()
    if not row or not row["enabled"] or not row["sealed_key"]:
        audit("refused:disabled")
        raise HTTPException(status_code=409, detail=f"{SOURCES[source][0]} is not enabled for this tenant")
    now = datetime.datetime.now(datetime.timezone.utc)
    if row["cooldown_until"] and row["cooldown_until"] > now:
        audit("refused:cooldown")
        raise HTTPException(status_code=429, detail=f"{SOURCES[source][0]} is rate-limited; try again later")
    budget = row["daily_budget"] if row["daily_budget"] is not None else SOURCES[source][1]
    used = db.execute(text("SELECT count(*) FROM source_calls WHERE tenant_key=:t AND source=:s "
                           "AND called_at >= date_trunc('day', :now)"), {"t": tenant, "s": source, "now": now}).scalar_one()
    if used >= budget:
        audit("refused:budget")
        raise HTTPException(status_code=429, detail=f"daily budget reached for {SOURCES[source][0]}")

    try:
        key = secrets_crypto.open(settings.key_encryption_key, tenant, source, row["sealed_key"])
    except secrets_crypto.KeyEncryptionError:
        audit("error:key")
        raise HTTPException(status_code=500, detail="could not open the stored key") from None

    try:
        verdict = ip_sources.LOOKUPS[source](ip, key)
    except ip_sources.IPSourceQuotaExceeded:
        db.execute(text("UPDATE tenant_source_keys SET cooldown_until=:u WHERE tenant_key=:t AND source=:s"),
                   {"u": now + datetime.timedelta(seconds=65), "t": tenant, "s": source})
        db.execute(text("INSERT INTO source_calls (tenant_key, source, indicator, http_status, outcome) "
                        "VALUES (:t,:s,:i,429,'quota_exceeded')"), {"t": tenant, "s": source, "i": ip})
        audit("quota_exceeded")
        raise HTTPException(status_code=429, detail=f"{SOURCES[source][0]} rate limit reached") from None
    except ip_sources.IPSourceAuthError:
        audit("error:auth")
        raise HTTPException(status_code=502, detail=f"{SOURCES[source][0]} rejected the key") from None
    except (ip_sources.IPSourceError, OSError, ValueError):
        audit("error:source")
        raise HTTPException(status_code=502, detail=f"{SOURCES[source][0]} lookup failed") from None

    ttl_hours = row["cache_ttl_hours"] if row["cache_ttl_hours"] is not None else SOURCES[source][2]
    itype = "ipv6" if ":" in ip else "ipv4"
    db.execute(text(
        "INSERT INTO source_verdicts (tenant_key, source, indicator, indicator_type, status, data, fetched_at, expires_at) "
        "VALUES (:t,:s,:i,:it,:st,CAST(:d AS jsonb),:now,:exp) "
        "ON CONFLICT (tenant_key, source, indicator) DO UPDATE SET status=EXCLUDED.status, data=EXCLUDED.data, "
        "fetched_at=EXCLUDED.fetched_at, expires_at=EXCLUDED.expires_at"),
        {"t": tenant, "s": source, "i": ip, "it": itype, "st": verdict["status"],
         "d": json.dumps(verdict["data"]), "now": now, "exp": now + datetime.timedelta(hours=ttl_hours)})
    db.execute(text("INSERT INTO source_calls (tenant_key, source, indicator, http_status, outcome) "
                    "VALUES (:t,:s,:i,200,:o)"), {"t": tenant, "s": source, "i": ip, "o": verdict["status"]})
    audit(f"ok:{verdict['status']}")
    return _verdict_response(source, ip, verdict["status"], verdict["data"], now, "live")
