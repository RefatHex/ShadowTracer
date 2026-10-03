"""RBAC (Step 3): a single dependency enforces role and tenant scoping on
every route. The enumeration test (tests/test_rbac_enumeration.py) walks
every registered route and fails if it finds one whose dependencies
contain neither a RequireRole instance nor the explicit `mark_public`
sentinel - no route can silently skip this by omission.
"""

import dataclasses

import jwt
from fastapi import Depends, HTTPException, Request

from .config import Settings
from .deps import get_settings
from .security import decode_access_token


@dataclasses.dataclass
class CurrentUser:
    user_id: int
    tenant_id: int
    tenant_key: str
    role: str


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return header[len("Bearer "):].strip()


class RequireRole:
    """Depends(RequireRole("admin")) or Depends(RequireRole("admin", "analyst")).
    Decodes and validates the access token, enforces the role is one of
    the allowed set, and returns a CurrentUser - the ONLY sanctioned way a
    route handler learns the caller's tenant_id, so every query a handler
    makes is scoped to it by construction, not by each handler remembering to."""

    def __init__(self, *allowed_roles: str):
        if not allowed_roles:
            raise ValueError("RequireRole needs at least one allowed role")
        self.allowed_roles = allowed_roles

    def __call__(self, request: Request, settings: Settings = Depends(get_settings)) -> CurrentUser:
        token = _extract_bearer_token(request)
        try:
            payload = decode_access_token(settings.jwt_secret, token)
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="invalid or expired token")

        role = payload.get("role")
        if role not in self.allowed_roles:
            raise HTTPException(status_code=403, detail="insufficient role")

        user = CurrentUser(
            user_id=int(payload["sub"]), tenant_id=payload["tenant_id"],
            tenant_key=payload["tenant_key"], role=role,
        )
        request.state.current_user = user
        return user


ALL_ROLES = RequireRole("admin", "analyst", "viewer")
ADMIN_ONLY = RequireRole("admin")
ANALYST_OR_ABOVE = RequireRole("admin", "analyst")


def mark_public() -> None:
    """Explicit opt-out marker for routes that must NOT require auth
    (login, refresh, health liveness). Depends(mark_public) - the
    enumeration test treats this, and only this, as a deliberate
    exemption; a route with neither this nor a RequireRole dependency
    fails the test instead of silently passing."""
    return None
