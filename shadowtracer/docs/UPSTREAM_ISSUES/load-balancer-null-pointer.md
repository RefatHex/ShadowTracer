Drafted for submission to github.com/wazuh/wazuh. Not filed - this fork
has no standing to file on the user's behalf. Written so it's ready to
paste in once reviewed.

---

**Title:** `OS_IsValidIP("any", ...)` doesn't set `is_ipv6`, causing a
NULL-pointer read in `isSingleHost()` and breaking dynamic-ID agent
identification behind a shared-IP load balancer

**Component:** `src/shared/validate_op.c`, `src/headers/validate_op.h`

**Summary:**

`OS_IsValidIP()`'s handling of the wildcard address `"any"` allocates
`final_ip->ipv6` but never sets `final_ip->is_ipv6 = TRUE` to match:

```c
else {
    /* any case */
    if (final_ip) {
        os_calloc(1, sizeof(os_ipv6), final_ip->ipv6);
        memset(final_ip->ipv6->ip_address, 0, sizeof(final_ip->ipv6->ip_address));
        memset(final_ip->ipv6->netmask, 0, sizeof(final_ip->ipv6->netmask));
        /* is_ipv6 left at memset(0)'s default of FALSE */
    }
    ret = 2;
}
```

`final_ip->ipv4` is never allocated for this path (it's `NULL`, left over
from `memset(final_ip, 0, sizeof(os_ip))` earlier in the function).
`isSingleHost()` (`src/headers/validate_op.h`) then reads:

```c
#define isSingleHost(x) ((x->is_ipv6) ? false : (x->ipv4->netmask == 0xFFFFFFFF))
```

Since `is_ipv6` is `FALSE` for an `"any"`-built `os_ip`, this evaluates
`x->ipv4->netmask` - a NULL-pointer dereference.

**Observable impact:** `src/os_crypto/shared/msgs.c`'s `CreateSecMSG()`
uses `!isSingleHost(...) && isAgent` to decide whether to prepend the
dynamic-ID `!<id>!` prefix that lets `wazuh-remoted` identify an
"any"-registered (dynamic IP) agent. With the undefined read above, this
check doesn't reliably evaluate true, so the prefix isn't sent - and
`wazuh-remoted` falls back to IP-based lookup, which can never
disambiguate multiple dynamic-IP agents sharing one source address (e.g.
several agents behind one TCP load balancer, or any NAT). In our testing
this manifested as *every* "any"-registered agent getting stuck in a
connect-close-retry loop, confirmed via packet capture showing the raw
`#AES:<data>` payload with no `!<id>!` prefix - even when pointed directly
at a single manager, bypassing any load balancer.

**Reproduction (unit-level):**

```c
os_ip *ret_ip;
os_calloc(1, sizeof(os_ip), ret_ip);
OS_IsValidIP("any", ret_ip);
/* ret_ip->is_ipv6 is FALSE, ret_ip->ipv4 is NULL */
isSingleHost(ret_ip); /* reads ret_ip->ipv4->netmask - NULL deref */
```

**Reproduction (end-to-end):** register an agent with a dynamic IP
(`agent-auth` without `-I`), point several such agents at a shared-IP TCP
load balancer in front of two or more managers, observe none of them ever
reach `Active`.

**Suggested fix:**

```c
else {
    /* any case */
    if (final_ip) {
        os_calloc(1, sizeof(os_ipv6), final_ip->ipv6);
        memset(final_ip->ipv6->ip_address, 0, sizeof(final_ip->ipv6->ip_address));
        memset(final_ip->ipv6->netmask, 0, sizeof(final_ip->ipv6->netmask));
        final_ip->is_ipv6 = TRUE;
    }
    ret = 2;
}
```

We'd also suggest hardening `isSingleHost()` itself as defense in depth
against the same class of mismatch elsewhere:

```c
#define isSingleHost(x) ((x->is_ipv6 || !x->ipv4) ? false : (x->ipv4->netmask == 0xFFFFFFFF))
```

**Validation:** re-verified end-to-end after the fix - agents registered
with a dynamic IP behind a real HAProxy TCP load balancer in front of two
managers now reach `Active`, and a 20-event worker-outage/failover test
through the load balancer delivered 20/20 (previously untestable through
the LB at all - the existing workaround was registering every agent with
a static IP and routing each to one specific manager directly,
sidestepping the load balancer entirely).

Also updated the one existing unit test that asserted the buggy behavior
as expected (`OS_IsValidIP_any_struct` in
`src/unit_tests/shared/test_validate_op.c` previously asserted
`is_ipv6 == FALSE` for `"any"`) and added a direct `isSingleHost()`
assertion alongside it. **Note:** this CMocka test has not been executed
in our environment (unrelated build dependencies in `syscollector`'s test
suite) - we believe it's correct by inspection, but the end-to-end
validation above is what we've actually run and observed pass.

**Patch:** see the diff in this fork's `src/shared/validate_op.c` /
`src/headers/validate_op.h` (search commit log for "Phase 3 follow-up") -
happy to open a PR with the equivalent change against a clean checkout if
maintainers want it in that form instead.
