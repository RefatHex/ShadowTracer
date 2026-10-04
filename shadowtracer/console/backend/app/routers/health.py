from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from .. import health as health_checks
from ..deps import get_db, get_settings
from ..rbac import ADMIN_ONLY, mark_public

router = APIRouter(tags=["health"])


@router.get("/health", dependencies=[Depends(mark_public)])
def health():
    """Liveness only: the process is running and can answer HTTP. No
    dependency checks - that's /health/ready's job."""
    return {"status": "ok"}


@router.get("/health/ready", dependencies=[Depends(mark_public)])
def health_ready(response: Response, db: Session = Depends(get_db), settings=Depends(get_settings)):
    report = health_checks.readiness_report(db, settings)
    response.status_code = 200 if report["ready"] else 503
    return report


@router.get("/health/detail")
def health_detail(settings=Depends(get_settings), _=Depends(ADMIN_ONLY)):
    """Admin-only: shipper lag per node, writer consumer lag, last event
    time per tenant, and dead-lettered event counts per tenant -
    operational detail, not something every logged-in user should see."""
    return {
        "shipper_lag": health_checks.shipper_lag_per_node(settings),
        "writer_consumer_lag": health_checks.writer_consumer_lag(settings),
        "last_event_time_per_tenant": health_checks.last_event_time_per_tenant(settings),
        "dead_letter_counts": health_checks.dead_letter_counts_per_tenant(settings),
    }
