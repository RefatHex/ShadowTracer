import threading

import pytest

from shadowtracer_ingest.retry import retry_with_backoff


def test_retry_succeeds_after_transient_failures():
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise ConnectionError("db unreachable")
        return "ok"

    result = retry_with_backoff(flaky, max_attempts=5, base_delay=0.01, max_delay=0.01)
    assert result == "ok"
    assert len(attempts) == 3


def test_retry_raises_after_max_attempts_exhausted():
    def always_fails():
        raise ConnectionError("db unreachable")

    with pytest.raises(ConnectionError):
        retry_with_backoff(always_fails, max_attempts=3, base_delay=0.01, max_delay=0.01)


def test_retry_forever_keeps_going_past_what_a_bounded_retry_would_give_up_at():
    """max_attempts=None is the transient-failure contract (writer.py's
    ClickHouse insert path): never give up, never dead-letter - just keep
    retrying. Proves it survives more failures than any bounded
    max_attempts here would tolerate."""
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 10:
            raise ConnectionError("db unreachable")
        return "ok"

    result = retry_with_backoff(flaky, max_attempts=None, base_delay=0.01, max_delay=0.01)
    assert result == "ok"
    assert len(attempts) == 10


def test_retry_forever_stops_early_when_stop_flag_fires():
    """A graceful shutdown must interrupt an indefinite retry instead of
    blocking it forever - stop_flag firing during the backoff wait raises
    the last exception rather than sleeping it out."""
    stop_flag = threading.Event()
    stop_flag.set()  # already set: the very first backoff wait returns immediately

    def always_fails():
        raise ConnectionError("db unreachable")

    with pytest.raises(ConnectionError):
        retry_with_backoff(always_fails, max_attempts=None, base_delay=10.0, max_delay=10.0, stop_flag=stop_flag)
