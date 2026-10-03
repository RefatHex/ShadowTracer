"""Login, lockout, and refresh-token rotation business logic (Step 2).
Kept separate from the FastAPI routes (routers/auth.py) so it's testable
without spinning up the HTTP layer.
"""

import datetime
from dataclasses import dataclass

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from . import security
from .models import login_attempts, refresh_tokens, tenants, users


@dataclass
class AuthenticatedUser:
    id: int
    tenant_id: int
    tenant_key: str
    email: str
    role: str


def record_login_attempt(db: Session, ip: str, email: str | None, success: bool) -> None:
    db.execute(login_attempts.insert().values(ip=ip, email=email, success=success))
    db.commit()


def is_locked_out(db: Session, ip: str, email: str | None, threshold: int, window_seconds: int) -> bool:
    """Locked if EITHER the IP or the account has >= threshold failed
    attempts within the window - independent checks, either one blocks."""
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=window_seconds)

    ip_failures = db.execute(
        select(func.count()).select_from(login_attempts).where(
            login_attempts.c.ip == ip,
            login_attempts.c.success.is_(False),
            login_attempts.c.created_at >= since,
        )
    ).scalar_one()
    if ip_failures >= threshold:
        return True

    if email:
        account_failures = db.execute(
            select(func.count()).select_from(login_attempts).where(
                login_attempts.c.email == email,
                login_attempts.c.success.is_(False),
                login_attempts.c.created_at >= since,
            )
        ).scalar_one()
        if account_failures >= threshold:
            return True

    return False


def authenticate(db: Session, email: str, password: str) -> AuthenticatedUser | None:
    """Returns None for: no such user, wrong password, inactive user, or a
    corrupted stored hash - the caller can't and shouldn't distinguish
    these (same generic "invalid credentials" response either way)."""
    row = db.execute(
        select(users, tenants.c.tenant_key)
        .join(tenants, tenants.c.id == users.c.tenant_id)
        .where(users.c.email == email, users.c.is_active.is_(True))
    ).mappings().first()
    if row is None:
        # Still run a verify against a dummy hash so a nonexistent-user
        # login takes roughly the same time as a wrong-password one -
        # cheap defense against timing-based user enumeration.
        security.verify_password(
            "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            password,
        )
        return None

    if not security.verify_password(row["password_hash"], password):
        return None

    if security.needs_rehash(row["password_hash"]):
        new_hash = security.hash_password(password)
        db.execute(users.update().where(users.c.id == row["id"]).values(password_hash=new_hash))
        db.commit()

    return AuthenticatedUser(
        id=row["id"], tenant_id=row["tenant_id"], tenant_key=row["tenant_key"],
        email=row["email"], role=row["role"],
    )


def issue_refresh_token(db: Session, user_id: int, family_id: str, ttl_seconds: int) -> str:
    token = security.new_refresh_token()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl_seconds)
    db.execute(
        refresh_tokens.insert().values(
            family_id=family_id,
            user_id=user_id,
            token_hash=security.hash_refresh_token(token),
            expires_at=expires_at,
        )
    )
    db.commit()
    return token


class RefreshTokenInvalid(Exception):
    pass


class RefreshTokenReplayed(Exception):
    """A used token was presented again - the whole family has been
    revoked as a side effect of raising this."""


def redeem_refresh_token(db: Session, presented_token: str, ttl_seconds: int) -> tuple[str, AuthenticatedUser]:
    """Validates and rotates a refresh token. Returns (new_token, user).
    Raises RefreshTokenInvalid (expired/unknown/revoked-family) or
    RefreshTokenReplayed (already-used token presented again - family is
    revoked before raising, as the whole point of detecting this)."""
    token_hash = security.hash_refresh_token(presented_token)
    row = db.execute(select(refresh_tokens).where(refresh_tokens.c.token_hash == token_hash)).mappings().first()
    if row is None:
        raise RefreshTokenInvalid("unknown token")

    if row["family_revoked"]:
        raise RefreshTokenInvalid("family revoked")

    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = row["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    if expires_at < now:
        raise RefreshTokenInvalid("expired")

    if row["used_at"] is not None:
        # Replay of an already-rotated-away token: assume compromise,
        # revoke every token in the family.
        db.execute(
            refresh_tokens.update()
            .where(refresh_tokens.c.family_id == row["family_id"])
            .values(family_revoked=True)
        )
        db.commit()
        raise RefreshTokenReplayed(f"family {row['family_id']} revoked")

    user_row = db.execute(
        select(users, tenants.c.tenant_key)
        .join(tenants, tenants.c.id == users.c.tenant_id)
        .where(users.c.id == row["user_id"])
    ).mappings().first()
    if user_row is None or not user_row["is_active"]:
        raise RefreshTokenInvalid("user no longer active")

    db.execute(refresh_tokens.update().where(refresh_tokens.c.id == row["id"]).values(used_at=now))
    new_token = issue_refresh_token(db, row["user_id"], row["family_id"], ttl_seconds)

    user = AuthenticatedUser(
        id=user_row["id"], tenant_id=user_row["tenant_id"], tenant_key=user_row["tenant_key"],
        email=user_row["email"], role=user_row["role"],
    )
    return new_token, user
