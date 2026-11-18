"""Phase 7.4 Part A unit checks for the terminal-ignore gate (no broker/DB).

Covers the two data-safety guarantees that the integration tests can only exercise
probabilistically: (1b) a tenant that becomes known only on a forced refresh is
processed, not ignored; (1c) a tenant that stays unknown is recorded countably
(global + per-topic counter, one-time log) before the caller advances the offset.
"""
import logging

from shadowtracer_ingest.metrics import Metrics
from shadowtracer_ingest.tenant_gate import ignore_unknown_tenant


class _Cache:
    """Fake TenantCache: `known_after_refresh` tenants appear only once force_refresh runs."""
    def __init__(self, known=(), known_after_refresh=()):
        self._known = set(known)
        self._pending = set(known_after_refresh)
        self.refreshes = 0

    def is_known(self, tk):
        return tk in self._known

    def force_refresh(self):
        self.refreshes += 1
        self._known |= self._pending
        self._pending = set()


def test_known_tenant_is_processed_without_refresh():
    c = _Cache(known={"t1"})
    assert ignore_unknown_tenant(c, "t1", logging.getLogger(), set(), Metrics(), "topic", 0) is False
    assert c.refreshes == 0


def test_just_provisioned_tenant_is_found_by_forced_refresh_not_ignored():
    # The 1b race: cache hasn't seen it yet, but its tenants row exists -> forced refresh finds it.
    c, m = _Cache(known_after_refresh={"t2"}), Metrics()
    assert ignore_unknown_tenant(c, "t2", logging.getLogger(), set(), m, "topic", 5) is False
    assert c.refreshes == 1
    assert m.snapshot().get("ignored_unknown_tenant", 0) == 0  # nothing skipped


def test_truly_unknown_tenant_is_ignored_and_recorded_countably():
    c, m, seen = _Cache(), Metrics(), set()
    topic = "shadowtracer.t.ghost.alerts"
    assert ignore_unknown_tenant(c, "ghost", logging.getLogger(), seen, m, topic, 42) is True
    assert c.refreshes == 1                                    # forced a refresh before giving up
    snap = m.snapshot()
    assert snap["ignored_unknown_tenant"] == 1                 # global counter
    assert snap[f"ignored_unknown_tenant:{topic}"] == 1        # per-topic counter (item 1c)
    # second message, same tenant: counted again, forced refresh NOT repeated, logged only once
    assert ignore_unknown_tenant(c, "ghost", logging.getLogger(), seen, m, topic, 43) is True
    assert c.refreshes == 1
    assert m.snapshot()[f"ignored_unknown_tenant:{topic}"] == 2


if __name__ == "__main__":
    test_known_tenant_is_processed_without_refresh()
    test_just_provisioned_tenant_is_found_by_forced_refresh_not_ignored()
    test_truly_unknown_tenant_is_ignored_and_recorded_countably()
    print("ok")
