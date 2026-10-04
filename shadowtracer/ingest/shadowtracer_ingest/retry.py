"""Exponential backoff for transient failures (a database or broker
being briefly unreachable) - the counterpart to dead_letter.py's "this
will never succeed" path. Shared by the writer and (imported the same
way as normalizer.py) the correlator, so both back off the same way
instead of hammering a down dependency in a tight loop.
"""

import time


def retry_with_backoff(fn, *, max_attempts=5, base_delay=1.0, max_delay=30.0, stop_flag=None, on_retry=None):
    """Calls fn() up to max_attempts times total, with exponential
    backoff between attempts (base_delay * 2**attempt, capped at
    max_delay). Returns fn()'s result on the first success. Re-raises the
    last exception if every attempt fails - the caller decides what "give
    up" means (e.g. dead-letter the batch). max_attempts=None retries
    forever - for a failure presumed purely transient (e.g. a database
    unreachable) that must never be given up on or dead-lettered; the
    only way this returns early then is stop_flag firing during a wait,
    for a graceful shutdown. Checks stop_flag between attempts, if given,
    so a graceful shutdown isn't blocked by a long backoff sleep -
    returns early (raising the last exception) if it fires during the
    wait."""
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as exc:
            attempt += 1
            if on_retry is not None:
                on_retry(attempt, exc)
            if max_attempts is not None and attempt >= max_attempts:
                raise
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            if stop_flag is not None:
                if stop_flag.wait(delay):
                    raise
            else:
                time.sleep(delay)
