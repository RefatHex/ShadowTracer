"""Phase 5C Step 0: validates a message's tenant_key against the real
tenants row before ingest - a forged, stale, or already-deleted
tenant_key must never create silent orphaned data (incidents/events with
no backing tenant; this is what let a VERIFY script's replay section
quietly accumulate exactly that - see PHASE3_DATA_PLATFORM.md). Shared
by the writer and (imported the same way as dead_letter.py) the
correlator.

A small, periodically-refreshed cache, not a query per message: a
Postgres round trip per event would be wasteful, and a brand-new tenant
(created seconds ago) must still be recognized promptly, not only after
some long TTL - REFRESH_INTERVAL_SECONDS balances the two.

How the cache actually behaves for a BRAND-NEW tenant (asked and
answered precisely, not just "it's cached"): `is_known()` only triggers
a refresh on a MISS when the cache is already stale (hasn't refreshed in
the last REFRESH_INTERVAL_SECONDS). A new tenant's very first events can
therefore be dead-lettered as "unknown_tenant" for anywhere from 0
seconds up to just under REFRESH_INTERVAL_SECONDS after its tenants row
is created - and that upper bound only holds if SOME check (any
tenant_key, not necessarily this one) happens to land during that
window and force a refresh; under genuinely idle traffic the cache can
go longer without refreshing at all, so there is no hard ceiling, only
"no worse than REFRESH_INTERVAL_SECONDS after the next check that
happens to find the cache stale." This is a real, expected gap, not a
bug - and it is exactly what `backfill_dead_letter_events.py`'s sibling
script, `replay_unknown_tenant_dead_letters.py`, exists to close: once
the tenant genuinely exists, re-drive its dead-lettered events back
through the normal pipeline rather than leaving them stuck in
dead_letter_events forever.
"""

import threading
import time

from sqlalchemy import text

REFRESH_INTERVAL_SECONDS = 15.0


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
        can still be accepted for up to REFRESH_INTERVAL_SECONDS. That's
        fine: this exists to catch forged/stale tenant_keys, not to
        enforce a hard real-time deletion boundary."""
        with self._lock:
            known = tenant_key in self._known
            stale = (time.monotonic() - self._last_refresh) >= REFRESH_INTERVAL_SECONDS
        if known:
            return True
        if not stale:
            return False
        self._refresh()
        with self._lock:
            return tenant_key in self._known
