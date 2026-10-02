import pytest

from app.config import WeakSecretError, validate_jwt_secret


def test_missing_jwt_secret_refuses_to_start():
    with pytest.raises(WeakSecretError, match="required and not set"):
        validate_jwt_secret(None)
    with pytest.raises(WeakSecretError, match="required and not set"):
        validate_jwt_secret("")


@pytest.mark.parametrize("placeholder", ["changeme", "CHANGEME", "secret", "password", "dev"])
def test_placeholder_jwt_secret_refuses_to_start(placeholder):
    with pytest.raises(WeakSecretError, match="placeholder"):
        validate_jwt_secret(placeholder)


def test_short_jwt_secret_refuses_to_start():
    with pytest.raises(WeakSecretError, match="minimum is"):
        validate_jwt_secret("a" * 10)


def test_valid_jwt_secret_accepted():
    secret = "a" * 48
    assert validate_jwt_secret(secret) == secret


def test_secret_file_takes_priority_over_literal_env(tmp_path, monkeypatch):
    from app.config import _env_or_file

    secret_file = tmp_path / "jwt_secret"
    secret_file.write_text("from-the-file-" + "x" * 40 + "\n")
    monkeypatch.setenv("JWT_SECRET", "from-the-literal-env-var")
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret_file))

    assert _env_or_file("JWT_SECRET") == "from-the-file-" + "x" * 40
