import pytest

from app import security
from app.auth import (
    AuthenticatedUser, RefreshTokenInvalid, RefreshTokenReplayed,
    authenticate, is_locked_out, issue_refresh_token, record_login_attempt,
    redeem_refresh_token,
)
from app.models import refresh_tokens, users


def _make_user(db, tenant_id, email="alice@example.com", password="correct horse battery staple", role="analyst"):
    result = db.execute(
        users.insert().values(
            tenant_id=tenant_id, email=email,
            password_hash=security.hash_password(password), role=role,
        ).returning(users.c.id)
    )
    db.commit()
    return result.scalar_one()


def test_authenticate_correct_credentials(db, tenant_id):
    _make_user(db, tenant_id)
    user = authenticate(db, "alice@example.com", "correct horse battery staple")
    assert user is not None
    assert user.email == "alice@example.com"
    assert user.role == "analyst"


def test_authenticate_wrong_password_returns_none(db, tenant_id):
    _make_user(db, tenant_id)
    assert authenticate(db, "alice@example.com", "wrong password") is None


def test_authenticate_nonexistent_user_returns_none_not_error(db, tenant_id):
    assert authenticate(db, "nobody@example.com", "whatever") is None


def test_authenticate_rehashes_weak_password_on_successful_verify(db, tenant_id):
    from argon2 import PasswordHasher, Type

    weak_hasher = PasswordHasher(type=Type.ID, time_cost=1, memory_cost=8, parallelism=1)
    weak_hash = weak_hasher.hash("correct horse battery staple")
    db.execute(
        users.insert().values(
            tenant_id=tenant_id, email="weak@example.com",
            password_hash=weak_hash, role="viewer",
        )
    )
    db.commit()

    user = authenticate(db, "weak@example.com", "correct horse battery staple")
    assert user is not None

    stored_now = db.execute(users.select().where(users.c.id == user.id)).mappings().first()
    assert stored_now["password_hash"] != weak_hash
    assert stored_now["password_hash"].startswith("$argon2id$")


# --- lockout -----------------------------------------------------------

def test_lockout_per_ip_across_different_accounts(db, tenant_id):
    """Repeated failures spread across several DIFFERENT accounts from the
    SAME ip must still trigger IP-based lockout."""
    for i in range(5):
        record_login_attempt(db, ip="10.0.0.5", email=f"user{i}@example.com", success=False)
    assert is_locked_out(db, ip="10.0.0.5", email="someone-else@example.com", threshold=5, window_seconds=900)


def test_lockout_per_account_across_different_ips(db, tenant_id):
    for i in range(5):
        record_login_attempt(db, ip=f"10.0.0.{i}", email="victim@example.com", success=False)
    assert is_locked_out(db, ip="10.0.0.99", email="victim@example.com", threshold=5, window_seconds=900)


def test_no_lockout_below_threshold(db, tenant_id):
    for i in range(3):
        record_login_attempt(db, ip="10.0.0.5", email="user@example.com", success=False)
    assert not is_locked_out(db, ip="10.0.0.5", email="user@example.com", threshold=5, window_seconds=900)


def test_successful_attempts_do_not_count_toward_lockout(db, tenant_id):
    for _ in range(10):
        record_login_attempt(db, ip="10.0.0.5", email="user@example.com", success=True)
    assert not is_locked_out(db, ip="10.0.0.5", email="user@example.com", threshold=5, window_seconds=900)


# --- refresh token rotation and replay ----------------------------------

def test_refresh_token_rotation_issues_a_new_token(db, tenant_id):
    user_id = _make_user(db, tenant_id)
    family_id = "fam-1"
    token1 = issue_refresh_token(db, user_id, family_id, ttl_seconds=3600)

    token2, user = redeem_refresh_token(db, token1, ttl_seconds=3600)
    assert token2 != token1
    assert user.id == user_id


def test_refresh_token_replay_revokes_the_whole_family(db, tenant_id):
    user_id = _make_user(db, tenant_id)
    family_id = "fam-2"
    token1 = issue_refresh_token(db, user_id, family_id, ttl_seconds=3600)

    token2, _ = redeem_refresh_token(db, token1, ttl_seconds=3600)

    # Replay token1 (already used) - must raise and revoke the family.
    with pytest.raises(RefreshTokenReplayed):
        redeem_refresh_token(db, token1, ttl_seconds=3600)

    # token2 (the legitimate next-in-line token) must now ALSO be rejected,
    # since the whole family was revoked, not just the replayed token.
    with pytest.raises(RefreshTokenInvalid, match="revoked"):
        redeem_refresh_token(db, token2, ttl_seconds=3600)


def test_unknown_refresh_token_rejected(db, tenant_id):
    with pytest.raises(RefreshTokenInvalid):
        redeem_refresh_token(db, "this-token-was-never-issued", ttl_seconds=3600)


def test_expired_refresh_token_rejected(db, tenant_id):
    user_id = _make_user(db, tenant_id)
    token = issue_refresh_token(db, user_id, "fam-3", ttl_seconds=-1)  # already expired
    with pytest.raises(RefreshTokenInvalid, match="expired"):
        redeem_refresh_token(db, token, ttl_seconds=3600)
