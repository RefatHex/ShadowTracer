"""Phase 7.4 Part A: the subscription gate shared by the writer and the correlator.

Both subscribe to ALERTS_TOPIC_PATTERN (a regex over every tenant's `.alerts` topic). A topic can
match that regex yet belong to a tenant that is NOT in the registry - an offboarded tenant with
in-flight events, or, on the shared lab broker, a test's own fixture topic. Such a message is
TERMINAL-IGNORED: logged once per tenant, its offset advanced, never dead-lettered. Dead-lettering
non-registry tenants was the only thing that filled the dead-letter topics (nothing consumes them
back, so there was never a true re-emit loop in production - see the loop trace); ignoring keeps
them empty too and removes the fodder the replay operator tool could churn on.

The tenant is validated against the registry (TenantCache.is_known, which refreshes on a miss), not
merely against the regex - so a genuinely new tenant whose topic was just provisioned is still
accepted; only a tenant the registry does not know is ignored.
"""


def ignore_unknown_tenant(tenant_cache, tenant_key: str, logger, seen: set, metrics, topic: str,
                          offset) -> bool:
    """True iff `tenant_key` is not in the registry: the caller should skip the message (advance the
    offset) and NOT dead-letter it. False means the tenant is known - process it normally.

    Phase 7.4 Part A, data-safety (items 1b/1c): before ignoring a tenant we have not ignored
    before, force ONE registry refresh (bypassing TenantCache's 1s rate limit). A new tenant's
    `tenants` row is always committed before its topic exists, so a forced refresh always finds a
    legitimately-new tenant; only offboarded/stray tenants survive it. And since ignoring advances
    the offset (no dead-letter to replay later), a skip is recorded countably FIRST - a per-topic
    counter plus a one-time log naming the topic and the offset where skipping began - so exactly
    what was skipped is provable. The batch commit that advances past this message runs only after
    this returns True, so the record is always written before the offset moves."""
    tk = tenant_key or ""
    if tenant_cache.is_known(tk):
        return False
    first_time = tk not in seen
    if first_time:
        tenant_cache.force_refresh()      # item 1b: never drop a just-provisioned tenant's first event
        if tenant_cache.is_known(tk):
            return False
    metrics.incr("ignored_unknown_tenant")             # global counter (dashboards / existing tests)
    metrics.incr(f"ignored_unknown_tenant:{topic}")    # item 1c: per-topic count == size of skipped offset range
    if first_time:
        seen.add(tk)
        logger.warning(
            "ignoring messages for non-registry tenant %r: topic %s, skipping from offset %s "
            "(matched the subscription pattern but the tenant is not in the registry after a forced "
            "refresh - offboarded, or a stray/test topic on a shared broker). Logged once; count in "
            "metric ignored_unknown_tenant:%s; offset advanced; NOT dead-lettered.",
            tk, topic, offset, topic)
    return True
