"""TenantCache: real isolated test Postgres (see conftest.py) - no mocks."""

import time
import uuid

from conftest import insert_tenant
from shadowtracer_ingest.tenants import REFRESH_RATE_LIMIT_SECONDS, TenantCache


def test_known_tenant_found_on_first_check(pg_engine, pg_db):
    tenant_key = f"test-{uuid.uuid4().hex[:8]}"
    insert_tenant(pg_db, tenant_key)

    cache = TenantCache(pg_engine)
    assert cache.is_known(tenant_key) is True
    assert cache.is_known(f"unknown-{uuid.uuid4().hex[:8]}") is False


def test_brand_new_tenant_recognized_immediately_when_cache_is_not_rate_limited(pg_engine, pg_db):
    """The common case the fix targets: a cache that hasn't refreshed
    recently (never, here) must recognize a tenant created moments ago on
    its very first check - no waiting for some other check to land."""
    cache = TenantCache(pg_engine)
    tenant_key = f"test-{uuid.uuid4().hex[:8]}"
    insert_tenant(pg_db, tenant_key)
    assert cache.is_known(tenant_key) is True


def test_a_miss_within_the_rate_limit_window_does_not_refresh(pg_engine, pg_db):
    """The one accepted gap, now bounded to REFRESH_RATE_LIMIT_SECONDS
    (1s) instead of the old 15s: a refresh that happened moments ago
    (here, simulated instead of waiting out a real prior refresh) blocks
    an immediate second refresh for a DIFFERENT, just-created tenant -
    by design, to avoid hammering Postgres once per message in a burst."""
    cache = TenantCache(pg_engine)
    cache._refresh()  # establishes a real "just refreshed" baseline
    tenant_key = f"test-{uuid.uuid4().hex[:8]}"
    insert_tenant(pg_db, tenant_key)
    assert cache.is_known(tenant_key) is False, "rate-limited: must not refresh again this soon"

    time.sleep(REFRESH_RATE_LIMIT_SECONDS + 0.2)
    assert cache.is_known(tenant_key) is True, "past the rate-limit window, the next miss must refresh and find it"
