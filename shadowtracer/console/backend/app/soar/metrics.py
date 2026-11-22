"""SOAR metrics (Phase 9 I). Per tenant, over a window, from soar_actions + incidents — no new
storage. Timeline per incident: first alert (incidents.first_seen) → incident
(incidents.created_at) → action requested (soar_actions.created_at) → executed
(soar_actions.executed_at). Rates: automation (auto vs human executions), undo, and
false-positive actions (actions on incidents an analyst later verdicted false_positive).
"""

import datetime

from sqlalchemy import text

DEFAULT_WINDOW_DAYS = 30


def compute(db, tenant_key: str, since: datetime.datetime | None = None) -> dict:
    if since is None:
        since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=DEFAULT_WINDOW_DAYS)

    counts = db.execute(text("""
        SELECT status, count(*) AS n FROM soar_actions
        WHERE tenant_key = :t AND created_at >= :since GROUP BY status
    """), {"t": tenant_key, "since": since}).mappings().all()
    by_status = {r["status"]: r["n"] for r in counts}
    executed = by_status.get("executed", 0) + by_status.get("undone", 0) + by_status.get("expired", 0)

    # stage timings (mean seconds) + automation/undo, over executed actions in the window
    stage = db.execute(text("""
        SELECT
          avg(extract(epoch FROM i.created_at - i.first_seen))        AS mttd,
          avg(extract(epoch FROM a.created_at - i.created_at))        AS to_request,
          avg(extract(epoch FROM a.executed_at - a.created_at))       AS to_execute,
          avg(extract(epoch FROM a.executed_at - i.first_seen))       AS mttc,
          count(*) FILTER (WHERE a.approved_by = 'auto')              AS auto_exec,
          count(*)                                                    AS all_exec
        FROM soar_actions a JOIN incidents i ON i.id = a.incident_id
        WHERE a.tenant_key = :t AND a.executed_at IS NOT NULL AND a.created_at >= :since
    """), {"t": tenant_key, "since": since}).mappings().first()

    undone = by_status.get("undone", 0)
    all_exec = stage["all_exec"] or 0
    auto_exec = stage["auto_exec"] or 0

    # false-positive actions: actions on incidents the analyst later verdicted
    fp = db.execute(text("""
        SELECT
          count(*) FILTER (WHERE i.triage_status = 'false_positive')          AS fp,
          count(*) FILTER (WHERE i.triage_status IN ('escalated','false_positive')) AS verdicted
        FROM soar_actions a JOIN incidents i ON i.id = a.incident_id
        WHERE a.tenant_key = :t AND a.status IN ('executed','undone','expired') AND a.created_at >= :since
    """), {"t": tenant_key, "since": since}).mappings().first()

    def rate(num, den):
        return round(num / den, 4) if den else None

    def secs(v):
        return round(float(v), 1) if v is not None else None

    return {
        "window_start": since.isoformat(),
        "counts": by_status,
        "executions": all_exec,
        "mttd_seconds": secs(stage["mttd"]),             # first alert -> incident
        "mttc_seconds": secs(stage["mttc"]),             # first alert -> contained (executed)
        "mean_to_request_seconds": secs(stage["to_request"]),
        "mean_to_execute_seconds": secs(stage["to_execute"]),   # approve->execute (MTTR of the human step)
        "automation_rate": rate(auto_exec, all_exec),    # auto executions / all executions
        "undo_rate": rate(undone, executed),
        "false_positive_action_rate": rate(fp["fp"], fp["verdicted"]),
    }
