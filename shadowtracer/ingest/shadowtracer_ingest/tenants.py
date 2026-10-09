"""Phase 5C Step 0: validates a message's tenant_key against the real
tenants row before ingest - a forged, stale, or already-deleted
tenant_key must never create silent orphaned data (incidents/events with
no backing tenant; this is what let a VERIFY script's replay section
quietly accumulate exactly that - see PHASE3_DATA_PLATFORM.md). Shared
by the writer and (imported the same way as dead_letter.py) the
correlator.

A small cache, not a query per message: a Postgres round trip per event
would be wasteful. On a MISS, `is_known()` refreshes immediately,
RATE-LIMITED to at most once per REFRESH_RATE_LIMIT_SECONDS - so a burst
of events for an unknown (or just-created) tenant doesn't hammer
Postgres once per message, but a brand-new tenant's very first event is
still recognized right away in the common case.

The real maximum window for a brand-new tenant (measured precisely, not
"it's cached"): if the cache's last refresh was more than
REFRESH_RATE_LIMIT_SECONDS ago, a miss refreshes immediately and finds
it - the common case, including a tenant's literal first-ever event
against a cache that hasn't refreshed recently. The one case this can't
close: if some OTHER tenant's check already forced a refresh within the
last REFRESH_RATE_LIMIT_SECONDS, a miss immediately afterward is
rate-limited and returns unknown without refreshing, so the new tenant's
event is dead-lettered until a check lands after that window - a
worst case of just under REFRESH_RATE_LIMIT_SECONDS (1 second), not the
much looser "no hard ceiling under idle traffic" the previous
15-second-window design had. Recoverable either way via
`replay_unknown_tenant_dead_letters.py` (see its own docstring).
"""

import threading
import time

from sqlalchemy import text

REFRESH_RATE_LIMIT_SECONDS = 1.0


class TenantCache:
    def __init__(self, engine):
        self._engine = engine
        self._lock = threading.Lock()
        self._known: set[str] = set()
        self._last_refresh = 0.0

    def _refresh(self) -> None:
        with self._engine.connect() as conn:
            rows = conn.execute(text("SELECT tenant_key FROM tenants")).scalars().all()
        with self._lock:
            self._known = set(rows)
            self._last_refresh = time.monotonic()

    def is_known(self, tenant_key: str) -> bool:
        """A positive result from the cache is always trusted - never
        re-verified against Postgres - so a tenant deleted seconds ago
        can still be accepted for up to REFRESH_RATE_LIMIT_SECONDS.
        That's fine: this exists to catch forged/stale tenant_keys, not
        to enforce a hard real-time deletion boundary."""
        with self._lock:
            known = tenant_key in self._known
            rate_limited = (time.monotonic() - self._last_refresh) < REFRESH_RATE_LIMIT_SECONDS
        if known:
            return True
        if rate_limited:
            return False
        self._refresh()
        with self._lock:
            return tenant_key in self._known
