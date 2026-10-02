import logging

from app.logging_redact import RedactingFilter, register_secret


def _capture(logger_name, action):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)

    import io
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)

    action(logger)
    handler.flush()
    return buf.getvalue()


def test_known_secret_value_never_appears_in_logs():
    secret = "sk-live-super-secret-12345"
    register_secret(secret)

    output = _capture("test.redact1", lambda log: log.info("connecting with api key %s", secret))

    assert secret not in output
    assert "REDACTED" in output


def test_password_key_value_pattern_redacted_even_if_not_pre_registered():
    output = _capture(
        "test.redact2",
        lambda log: log.info("login attempt password=hunter2-not-registered-anywhere"),
    )
    assert "hunter2-not-registered-anywhere" not in output
    assert "REDACTED" in output


def test_bearer_token_redacted():
    output = _capture(
        "test.redact3",
        lambda log: log.info("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.unregistered.sig"),
    )
    assert "eyJhbGciOiJIUzI1NiJ9" not in output
    assert "REDACTED" in output


def test_non_secret_messages_pass_through_unchanged():
    output = _capture("test.redact4", lambda log: log.info("user alice logged in from tenant lab"))
    assert "alice" in output
    assert "tenant lab" in output
