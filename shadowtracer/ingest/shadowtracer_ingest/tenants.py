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
