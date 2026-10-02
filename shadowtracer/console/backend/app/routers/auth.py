from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import auth as auth_logic
from .. import security
from ..deps import client_ip, get_db, get_settings
from ..logging_redact import register_secret
from ..rbac import mark_public

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(mark_public)])

REFRESH_COOKIE_NAME = "refresh_token"


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: int
    role: str


def _set_refresh_cookie(response: Response, token: str, ttl_seconds: int) -> None:
    register_secret(token)
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=ttl_seconds,
        path="/auth",
    )


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings=Depends(get_settings),
):
    ip = client_ip(request)

    if auth_logic.is_locked_out(db, ip, body.email, settings.lockout_threshold, settings.lockout_window_seconds):
        # Record the attempt anyway - a lockout check alone shouldn't
        # reset the clock on the lockout window.
        auth_logic.record_login_attempt(db, ip, body.email, success=False)
        raise HTTPException(status_code=401, detail="invalid credentials")

    user = auth_logic.authenticate(db, body.email, body.password)
    auth_logic.record_login_attempt(db, ip, body.email, success=user is not None)

    if user is None:
        raise HTTPException(status_code=401, detail="invalid credentials")

    access_token = security.create_access_token(
        settings.jwt_secret, user.id, user.tenant_id, user.role, settings.access_token_ttl_seconds,
    )
    register_secret(access_token)

    family_id = security.new_family_id()
    refresh_token = auth_logic.issue_refresh_token(db, user.id, family_id, settings.refresh_token_ttl_seconds)
    _set_refresh_cookie(response, refresh_token, settings.refresh_token_ttl_seconds)

    return TokenResponse(access_token=access_token, tenant_id=user.tenant_id, role=user.role)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    response: Response,
    db: Session = Depends(get_db),
    settings=Depends(get_settings),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="no refresh token")

    try:
        new_token, user = auth_logic.redeem_refresh_token(db, refresh_token, settings.refresh_token_ttl_seconds)
    except auth_logic.RefreshTokenReplayed:
        response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth")
        raise HTTPException(status_code=401, detail="refresh token reuse detected, session revoked")
    except auth_logic.RefreshTokenInvalid:
        response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth")
        raise HTTPException(status_code=401, detail="invalid refresh token")

    _set_refresh_cookie(response, new_token, settings.refresh_token_ttl_seconds)
    access_token = security.create_access_token(
        settings.jwt_secret, user.id, user.tenant_id, user.role, settings.access_token_ttl_seconds,
    )
    register_secret(access_token)
    return TokenResponse(access_token=access_token, tenant_id=user.tenant_id, role=user.role)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth")
    return {"status": "logged out"}
