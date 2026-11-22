"""Safety rails (Phase 9 F), enforced in code before every containment action.

Two kinds of outcome:
  - hard refuse (allowed=False): kill switch, allowlist, anti-spoofing. No containment, ever.
  - downgrade (force_approval=True): circuit breaker tripped, or the tenant's hourly rate limit
    reached. The action is allowed but may only go through approval, never auto; exceeding the
    rate limit also trips the breaker (breaker_trip_reason set) so it stays approval-only and the
    tenant is notified (notifier lands in Phase 9 e).

Timed blocks, scope limit and idempotency are enforced by the caller (actions.py / worker.py):
block_seconds is always set and capped; scope limit bounds targets per run; the DB unique
constraint makes a repeat (incident, playbook, target) a no-op.
"""

import ipaddress
from dataclasses import dataclass


@dataclass
class Decision:
    allowed: bool
    refuse_reason: str | None = None
    force_approval: bool = False
    breaker_trip_reason: str | None = None


def is_allowlisted(ip: str, extra_cidrs: list[str], protected_ips: set[str]) -> tuple[bool, str | None]:
    """Internal/own/critical IPs are never a containment target. Returns (allowlisted, why)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Not a parseable IP -> cannot be safely blocked; treat as allowlisted (refuse) by caller.
        return True, "unparseable_ip"
    if ip in protected_ips:
        return True, "manager_or_agent_ip"
    if addr.is_private:
        return True, "rfc1918_internal"
    if addr.is_loopback:
        return True, "loopback"
    if addr.is_link_local:
        return True, "link_local"
    if addr.is_multicast:
        return True, "multicast"
    if addr.is_reserved or addr.is_unspecified:
        return True, "reserved"
    for cidr in extra_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True, f"admin_allowlist:{cidr}"
        except ValueError:
            continue
    return False, None


def anti_spoof_ok(observations: int, ti_confirmed: bool) -> bool:
    """Never block an IP corroborated by only a single log observation unless TI confirms it: a
    forged single log line naming an innocent IP must not trigger a block, while real activity
    (e.g. an SSH brute force = many failed-login alerts, even from one agent) has many. observations
    = number of alert records in the incident that evidence this IP."""
    return ti_confirmed or observations >= 2


def guard(ip: str, *, global_kill: bool, tenant_kill: bool, breaker_tripped: bool,
          allow_cidrs: list[str], protected_ips: set[str], observations: int,
          ti_confirmed: bool, actions_last_hour: int, rate_limit: int) -> Decision:
    if global_kill or tenant_kill:
        return Decision(False, "kill_switch")
    allow, why = is_allowlisted(ip, allow_cidrs, protected_ips)
    if allow:
        return Decision(False, f"allowlist:{why}")
    if not anti_spoof_ok(observations, ti_confirmed):
        return Decision(False, "anti_spoof:single_observation_no_ti")
    if actions_last_hour >= rate_limit:
        return Decision(True, force_approval=True, breaker_trip_reason="rate_limit")
    if breaker_tripped:
        return Decision(True, force_approval=True)
    return Decision(True)


def clamp_block_seconds(requested: int | None, default: int, maximum: int) -> int:
    """Every block is timed: fall back to the tenant default, cap at the admin maximum, floor at 1 s."""
    secs = requested if requested and requested > 0 else default
    return max(1, min(secs, maximum))


if __name__ == "__main__":  # self-check
    assert is_allowlisted("10.0.0.5", [], set())[0] is True            # RFC1918
    assert is_allowlisted("127.0.0.1", [], set())[0] is True           # loopback
    assert is_allowlisted("8.8.8.8", [], set())[0] is False            # public attacker: blockable
    assert is_allowlisted("8.8.8.8", [], {"8.8.8.8"})[0] is True       # an agent's own IP
    assert is_allowlisted("203.0.113.9", ["203.0.113.0/24"], set())[0] is True  # admin allowlist
    assert anti_spoof_ok(1, False) is False                            # single forged observation, no TI
    assert anti_spoof_ok(1, True) is True                              # TI overrides
    assert anti_spoof_ok(2, False) is True                             # corroborated
    assert guard("10.0.0.5", global_kill=False, tenant_kill=False, breaker_tripped=False,
                 allow_cidrs=[], protected_ips=set(), observations=5, ti_confirmed=True,
                 actions_last_hour=0, rate_limit=10).allowed is False  # internal refused
    assert guard("8.8.8.8", global_kill=True, tenant_kill=False, breaker_tripped=False,
                 allow_cidrs=[], protected_ips=set(), observations=5, ti_confirmed=True,
                 actions_last_hour=0, rate_limit=10).refuse_reason == "kill_switch"
    d = guard("8.8.8.8", global_kill=False, tenant_kill=False, breaker_tripped=False, allow_cidrs=[],
              protected_ips=set(), observations=5, ti_confirmed=True, actions_last_hour=10, rate_limit=10)
    assert d.allowed and d.force_approval and d.breaker_trip_reason == "rate_limit"
    assert clamp_block_seconds(None, 3600, 86400) == 3600
    assert clamp_block_seconds(999999, 3600, 86400) == 86400
    print("rails self-check ok")
