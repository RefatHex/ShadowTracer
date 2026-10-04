"""Phase 5A Step 5: the Attack Library - fingerprint list/detail with
occurrence history, verdicts, and admin-only label/notes/suppression
controls. Every query scoped to current_user.tenant_key, same rule as
everywhere else - fingerprints are tenant-scoped (see DECISIONS.md)."""

import datetime

import clickhouse_connect
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import incidents as incidents_logic
from ..audit import append_entry
from ..config import Settings
from ..deps import get_db, get_settings
from ..models import fingerprint_verdicts, fingerprints
from ..rbac import ADMIN_ONLY, ALL_ROLES, CurrentUser

router = APIRouter(prefix="/api", tags=["fingerprints"])


class FingerprintSummary(BaseModel):
    fingerprint_key: str
    label: str | None
    suppression_state: str
    suppression_expires_at: datetime.datetime | None
    occurrence_count: int


class VerdictCounts(BaseModel):
    acknowledged: int
    escalated: int
    false_positive: int
    distinct_false_positive_analysts: int


class FingerprintDetail(FingerprintSummary):
    notes: str | None
    verdicts: VerdictCounts
    occurrences: list[dict]


class UpdateFingerprintRequest(BaseModel):
    label: str | None = None
    notes: str | None = None


class SuppressRequest(BaseModel):
    expiry_days: int = incidents_logic.SUPPRESSION_EXPIRY_DAYS


def _get_ch_client(settings: Settings):
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host, port=settings.clickhouse_port,
        username=settings.clickhouse_user, password=settings.clickhouse_password,
        database=settings.clickhouse_database,
    )


def _occurrence_count(ch_client, tenant_key: str, fingerprint_key: str) -> int:
    # Always uniqExact(incident_id), never count() - see
    # schema/events_schema.sql's fingerprint_occurrences header for why.
    result = ch_client.query(
        "SELECT uniqExact(incident_id) FROM fingerprint_occurrences "
        "WHERE tenant_id = {t:String} AND fingerprint_key = {f:String}",
        parameters={"t": tenant_key, "f": fingerprint_key},
    )
    return result.result_rows[0][0]


@router.get("/fingerprints", response_model=list[FingerprintSummary])
def list_fingerprints(
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ALL_ROLES),
):
    rows = db.execute(
        select(fingerprints).where(fingerprints.c.tenant_key == current_user.tenant_key)
    ).mappings().all()

    ch_client = _get_ch_client(settings)
    try:
        items = []
        for row in rows:
            state, _ = incidents_logic.effective_suppression_state(db, current_user.tenant_key, row["fingerprint_key"])
            items.append(FingerprintSummary(
                fingerprint_key=row["fingerprint_key"], label=row["label"],
                suppression_state=state, suppression_expires_at=row["suppression_expires_at"],
                occurrence_count=_occurrence_count(ch_client, current_user.tenant_key, row["fingerprint_key"]),
            ))
    finally:
        ch_client.close()

    # Suppressed fingerprints sink to the bottom of the default list -
    # Step 4: suppression "lowers placement in the default list", it
    # never removes anything from it.
    items.sort(key=lambda f: (f.suppression_state == "active", -f.occurrence_count))
    return items


@router.get("/fingerprints/{fingerprint_key}", response_model=FingerprintDetail)
def get_fingerprint(
    fingerprint_key: str,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ALL_ROLES),
):
    row = db.execute(
        select(fingerprints).where(
            fingerprints.c.tenant_key == current_user.tenant_key, fingerprints.c.fingerprint_key == fingerprint_key,
        )
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="fingerprint not found")

    state, _ = incidents_logic.effective_suppression_state(db, current_user.tenant_key, fingerprint_key)

    verdict_rows = db.execute(
        select(fingerprint_verdicts.c.verdict, func.count(), func.count(func.distinct(fingerprint_verdicts.c.analyst_user_id)))
        .where(
            fingerprint_verdicts.c.tenant_key == current_user.tenant_key,
            fingerprint_verdicts.c.fingerprint_key == fingerprint_key,
        )
        .group_by(fingerprint_verdicts.c.verdict)
    ).all()
    counts = {"acknowledged": 0, "escalated": 0, "false_positive": 0}
    distinct_fp_analysts = 0
    for verdict, count, distinct_analysts in verdict_rows:
        counts[verdict] = count
        if verdict == "false_positive":
            distinct_fp_analysts = distinct_analysts

    ch_client = _get_ch_client(settings)
    try:
        occurrence_count = _occurrence_count(ch_client, current_user.tenant_key, fingerprint_key)
        occurrence_rows = ch_client.query(
            "SELECT incident_id, closed_at, alert_count FROM fingerprint_occurrences "
            "WHERE tenant_id = {t:String} AND fingerprint_key = {f:String} ORDER BY closed_at DESC LIMIT 100",
            parameters={"t": current_user.tenant_key, "f": fingerprint_key},
        )
        occurrences = [
            {"incident_id": r[0], "closed_at": r[1].isoformat(), "alert_count": r[2]}
            for r in occurrence_rows.result_rows
        ]
    finally:
        ch_client.close()

    return FingerprintDetail(
        fingerprint_key=fingerprint_key, label=row["label"], notes=row["notes"],
        suppression_state=state, suppression_expires_at=row["suppression_expires_at"],
        occurrence_count=occurrence_count,
        verdicts=VerdictCounts(
            acknowledged=counts["acknowledged"], escalated=counts["escalated"],
            false_positive=counts["false_positive"], distinct_false_positive_analysts=distinct_fp_analysts,
        ),
        occurrences=occurrences,
    )


@router.patch("/fingerprints/{fingerprint_key}")
def update_fingerprint(
    fingerprint_key: str,
    body: UpdateFingerprintRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ADMIN_ONLY),
):
    row = db.execute(
        select(fingerprints.c.fingerprint_key).where(
            fingerprints.c.tenant_key == current_user.tenant_key, fingerprints.c.fingerprint_key == fingerprint_key,
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="fingerprint not found")

    values = {}
    if body.label is not None:
        values["label"] = body.label
    if body.notes is not None:
        values["notes"] = body.notes
    if values:
        values["updated_at"] = func.now()
        db.execute(
            fingerprints.update()
            .where(fingerprints.c.tenant_key == current_user.tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
            .values(**values)
        )
        append_entry(
            db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
            action="fingerprint_updated", target=fingerprint_key, outcome="success",
        )  # append_entry commits - also durably commits the UPDATE above, same transaction
    return {"status": "ok"}


@router.post("/fingerprints/{fingerprint_key}/suppress")
def suppress_fingerprint(
    fingerprint_key: str,
    body: SuppressRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(ADMIN_ONLY),
):
    try:
        expires_at = incidents_logic.approve_suppression(
            db, current_user.tenant_key, fingerprint_key, expiry_days=body.expiry_days,
        )
    except incidents_logic.FingerprintNotFound:
        raise HTTPException(status_code=404, detail="fingerprint not found")
    except incidents_logic.InvalidSuppressionTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    append_entry(
        db, actor=str(current_user.user_id), tenant_id=current_user.tenant_id,
        action="fingerprint_suppression_activated", target=fingerprint_key, outcome="success",
    )
    return {"suppression_state": "active", "suppression_expires_at": expires_at.isoformat()}
