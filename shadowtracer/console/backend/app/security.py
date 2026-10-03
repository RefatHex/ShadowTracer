"""Password hashing and JWT handling (Step 2).

argon2id variant is pinned explicitly (argon2.Type.ID), not left to
whatever argon2-cffi's PasswordHasher() default happens to be today - a
future library update changing its default must not silently change what
we verify against.
"""

import hashlib
import secrets
import time
import uuid

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_hasher = PasswordHasher(type=Type.ID)

ROLES = ("admin", "analyst", "viewer")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Returns False for a wrong password AND for a corrupted/invalid
    stored hash - callers (the login route) must turn either into a plain
    401, never let a hash-parsing exception become an unhandled 500."""
    try:
        return _hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError, ValueError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (VerificationError, InvalidHashError, ValueError):
        return False


def create_access_token(jwt_secret: str, user_id: int, tenant_id: int, tenant_key: str, role: str, ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "tenant_key": tenant_key,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
        "type": "access",
    }
    return jwt.encode(payload, jwt_secret, algorithm="HS256")


def decode_access_token(jwt_secret: str, token: str) -> dict:
    """Raises jwt.PyJWTError (expired, bad signature, malformed) - callers
    turn that into 401."""
    payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("not an access token")
    return payload


def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def new_family_id() -> str:
    return str(uuid.uuid4())


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
