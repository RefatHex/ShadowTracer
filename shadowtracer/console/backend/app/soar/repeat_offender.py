"""Repeat-offender escalation (Phase 9 follow-up A2), SOAR-owned. Wazuh's repeated_offenders does not
apply to API-dispatched custom scripts, so SOAR escalates the block duration itself: per tenant + IP,
count prior blocks on that IP inside the look-back window and pick the Nth step of the escalating
schedule (default 1h -> 6h -> 24h), capped at the tenant's admin maximum. The offense count and chosen
duration are recorded on the action (in its signals).
"""

import datetime

from sqlalchemy import text


def prior_block_count(db, tenant_key: str, ip: str, window_seconds: int,
                      now: datetime.datetime) -> int:
    """How many times this IP was already blocked (executed/undone/expired) within the window."""
    since = now - datetime.timedelta(seconds=window_seconds)
    return db.execute(text("""
        SELECT count(*) FROM soar_actions
        WHERE tenant_key = :t AND action_type = 'block_ip' AND target = :ip
          AND status IN ('executed','undone','expired') AND created_at >= :since
    """), {"t": tenant_key, "ip": ip, "since": since}).scalar() or 0


def escalated_seconds(schedule: list[int], offense_count: int, cap: int) -> int:
    """offense_count is the number of PRIOR offenses (0 = first block). Pick schedule[count], clamped
    to the last step, then capped at the admin maximum."""
    if not schedule:
        return cap
    step = schedule[min(offense_count, len(schedule) - 1)]
    return min(step, cap)


def duration_for(db, tenant_key: str, ip: str, *, schedule: list[int], window_seconds: int,
                 cap: int, now: datetime.datetime) -> tuple[int, int]:
    """-> (block_seconds, prior_offense_count)."""
    prior = prior_block_count(db, tenant_key, ip, window_seconds, now)
    return escalated_seconds(schedule, prior, cap), prior


if __name__ == "__main__":  # self-check
    sched = [3600, 21600, 86400]
    assert escalated_seconds(sched, 0, 999999) == 3600       # first offense -> 1h
    assert escalated_seconds(sched, 1, 999999) == 21600      # second -> 6h
    assert escalated_seconds(sched, 2, 999999) == 86400      # third -> 24h
    assert escalated_seconds(sched, 9, 999999) == 86400      # clamps to last step
    assert escalated_seconds(sched, 2, 7200) == 7200         # admin cap wins
    print("repeat_offender self-check ok")
