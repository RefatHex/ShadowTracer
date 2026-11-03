from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from .. import health as health_checks
from ..deps import get_db, get_settings
from ..rbac import ADMIN_ONLY, mark_public
from ..version import VERSION

router = APIRouter(tags=["health"])


@router.get("/health", dependencies=[Depends(mark_public)])
def health():
    """Liveness only: the process is running and can answer HTTP. No
    dependency checks - that's /health/ready's job."""
    return {"status": "ok", "version": VERSION}


@router.get("/health/ready", dependencies=[Depends(mark_public)])
def health_ready(response: Response, db: Session = Depends(get_db), settings=Depends(get_settings)):
    report = health_checks.readiness_report(db, settings)
    response.status_code = 200 if report["ready"] else 503
    return report


@router.get("/health/detail")
def health_detail(db: Session = Depends(get_db), settings=Depends(get_settings), _=Depends(ADMIN_ONLY)):
    """Admin-only: shipper lag per node, writer consumer lag, last event
    time per tenant, dead-lettered event counts per tenant, per-host
    ClickHouse replica health (dead-letter-ClickHouse incident,
    2026-10-08 - see clickhouse_replica_health's own docstring),
    per-manager clock skew (Phase 5C Step 0b - see clock_skew_per_node's
    own docstring), and components stuck in a dead-letter retry loop
    (Phase 5.6 closeout item 3 - see stuck_components' own docstring) -
    operational detail, not something every logged-in user should see."""
    return {
        "shipper_lag": health_checks.shipper_lag_per_node(settings),
        "writer_consumer_lag": health_checks.writer_consumer_lag(settings),
        "last_event_time_per_tenant": health_checks.last_event_time_per_tenant(settings),
        "dead_letter_counts": health_checks.dead_letter_counts_per_tenant(settings),
        "clickhouse_replica_health": health_checks.clickhouse_replica_health(settings),
        "clock_skew_per_node": health_checks.clock_skew_per_node(settings),
        "stuck_components": health_checks.stuck_components(db, settings.stuck_retry_alert_seconds),
    }
