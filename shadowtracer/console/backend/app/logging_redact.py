"""Log redaction (Step 1): secrets, tokens and passwords never appear in
logs. Two layers: an explicit registry of known secret values (exact
substring match - the JWT secret, DB/ClickHouse passwords, issued tokens)
and a regex pass for common key=value / header patterns, as a backstop
for secrets that were never explicitly registered (a bug, not a feature -
the registry should be the real defense)."""

import logging
import re
import threading

REDACTED = "***REDACTED***"

_lock = threading.Lock()
_known_secrets: set[str] = set()

_KEY_VALUE_PATTERN = re.compile(
    r'(?i)\b(password|passwd|token|secret|authorization|api[_-]?key)\b'
    r'(["\']?\s*[:=]\s*["\']?)([^\s"\',}]+)',
)
_BEARER_PATTERN = re.compile(r'(?i)\bBearer\s+([A-Za-z0-9\-_.]+)')


def register_secret(value: str) -> None:
    """Call this the moment a secret value is known (loaded from config,
    or issued as a token) so every log line is scrubbed against it."""
    if not value:
        return
    with _lock:
        _known_secrets.add(value)


def _redact_text(text: str) -> str:
    with _lock:
        secrets = list(_known_secrets)
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, REDACTED)
    # Bearer-token pattern first: "Authorization: Bearer <token>" would
    # otherwise partially match the key=value pattern below (which stops
    # at the first space, consuming only the word "Bearer" and leaving
    # the actual token untouched).
    text = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", text)
    text = _KEY_VALUE_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg = _redact_text(message)
        record.args = ()
        return True


def setup_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    redact_filter = RedactingFilter()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
    for handler in root.handlers:
        handler.addFilter(redact_filter)
