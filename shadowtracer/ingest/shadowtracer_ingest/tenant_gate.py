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


def ignore_unknown_tenant(tenant_cache, tenant_key: str, logger, seen: set) -> bool:
    """True iff `tenant_key` is not in the registry: the caller should skip the message (advance the
    offset) and NOT dead-letter it. Logs once per tenant. False means the tenant is known - process
    it normally."""
    if tenant_cache.is_known(tenant_key or ""):
        return False
    if tenant_key not in seen:
        seen.add(tenant_key)
        logger.warning(
            "ignoring messages for non-registry tenant %r: the topic matched the subscription "
            "pattern but the tenant is not in the registry (offboarded, or a stray/test topic on a "
            "shared broker). Logged once; offset advanced; NOT dead-lettered.", tenant_key)
    return True
