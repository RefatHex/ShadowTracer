from argon2 import Type

from app.security import hash_password, needs_rehash, verify_password


def test_argon2id_variant_is_pinned():
    # The variant is encoded directly in the hash string itself
    # ($argon2id$...) - the clearest possible proof the pinned Type.ID is
    # what's actually being produced, not just what the code claims to ask for.
    stored = hash_password("correct horse battery staple")
    assert stored.startswith("$argon2id$")


def test_correct_password_verifies():
    stored = hash_password("correct horse battery staple")
    assert verify_password(stored, "correct horse battery staple") is True


def test_wrong_password_fails_without_raising():
    stored = hash_password("correct horse battery staple")
    assert verify_password(stored, "wrong password") is False


def test_corrupted_hash_returns_false_never_raises():
    garbage_values = [
        "not-a-valid-hash-at-all",
        "$argon2id$v=19$truncated",
        "",
        "$bcrypt$2b$12$totallywrongformat",
    ]
    for garbage in garbage_values:
        assert verify_password(garbage, "any password") is False


def test_needs_rehash_false_for_freshly_hashed_password():
    stored = hash_password("correct horse battery staple")
    assert needs_rehash(stored) is False


def test_needs_rehash_handles_corrupted_hash_without_raising():
    assert needs_rehash("not-a-valid-hash") is False


def test_needs_rehash_true_for_weaker_parameters():
    from argon2 import PasswordHasher

    weak_hasher = PasswordHasher(type=Type.ID, time_cost=1, memory_cost=8, parallelism=1)
    weak_hash = weak_hasher.hash("correct horse battery staple")
    assert needs_rehash(weak_hash) is True
