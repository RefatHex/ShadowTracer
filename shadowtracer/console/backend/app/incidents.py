"""Phase 5A Step 2/4: incident triage and the fingerprint verdict/
suppression state machine. Kept separate from the FastAPI routes
(routers/incidents.py, routers/fingerprints.py) same as app/auth.py is
from routers/auth.py - audit logging stays in the routes, which already
know the caller's identity and already call append_entry for everything
else.
"""

import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import fingerprint_verdicts, fingerprints, incidents

# "comment" deliberately isn't here - it doesn't change triage_status or
# count as a verdict, it's just a note (see add_comment, which only
# writes an audit row with the comment text as its target).
TRIAGE_STATUS_FOR_ACTION = {
    "acknowledge": "acknowledged",
    "escalate": "escalated",
    "false_positive": "false_positive",
}

SUPPRESSION_FALSE_POSITIVE_THRESHOLD = 5
SUPPRESSION_MIN_DISTINCT_ANALYSTS = 2
SUPPRESSION_EXPIRY_DAYS = 90


class IncidentNotFound(Exception):
    pass


class FingerprintNotFound(Exception):
    pass


class InvalidSuppressionTransition(Exception):
    pass


def apply_triage(
    db: Session, tenant_key: str, incident_id: int, action: str, analyst_user_id: int,
) -> dict:
    """Updates triage_status and, for the 3 verdict-bearing actions,
    records a fingerprint_verdicts row and re-checks the suppression
    threshold. Returns enough for the caller to decide what to audit:
    {"triage_status", "fingerprint_key", "suppression_state_changed_to"}
    (the last is None unless this call just flipped none -> proposed)."""
    row = db.execute(
        select(incidents).where(incidents.c.id == incident_id, incidents.c.tenant_key == tenant_key)
    ).mappings().first()
    if row is None:
        raise IncidentNotFound(incident_id)

    new_triage_status = TRIAGE_STATUS_FOR_ACTION[action]
    db.execute(incidents.update().where(incidents.c.id == incident_id).values(triage_status=new_triage_status))

    suppression_state_changed_to = None
    if row["fingerprint_key"]:
        fingerprint_key = row["fingerprint_key"]
        db.execute(
            fingerprint_verdicts.insert().values(
                tenant_key=tenant_key, fingerprint_key=fingerprint_key, incident_id=incident_id,
                analyst_user_id=analyst_user_id, verdict=new_triage_status,
            )
        )
        if new_triage_status == "false_positive":
            suppression_state_changed_to = _maybe_propose_suppression(db, tenant_key, fingerprint_key)

    db.commit()
    return {
        "triage_status": new_triage_status,
        "fingerprint_key": row["fingerprint_key"],
        "suppression_state_changed_to": suppression_state_changed_to,
    }


def _maybe_propose_suppression(db: Session, tenant_key: str, fingerprint_key: str) -> str | None:
    """5+ false_positive verdicts from 2+ DISTINCT analysts flips
    none -> proposed. Never touches proposed or active here - becoming
    'active' is always a separate, explicit admin action
    (approve_suppression), never automatic: an attacker who can trigger
    their own benign-looking alerts must not be able to train the system
    into silently ignoring their own pattern."""
    total_count, distinct_analysts = db.execute(
        select(func.count(), func.count(func.distinct(fingerprint_verdicts.c.analyst_user_id)))
        .where(
            fingerprint_verdicts.c.tenant_key == tenant_key,
            fingerprint_verdicts.c.fingerprint_key == fingerprint_key,
            fingerprint_verdicts.c.verdict == "false_positive",
        )
    ).one()

    fp_row = db.execute(
        select(fingerprints).where(
            fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key
        )
    ).mappings().first()
    current_state = fp_row["suppression_state"] if fp_row else "none"

    if (
        current_state == "none"
        and total_count >= SUPPRESSION_FALSE_POSITIVE_THRESHOLD
        and distinct_analysts >= SUPPRESSION_MIN_DISTINCT_ANALYSTS
    ):
        db.execute(
            fingerprints.update()
            .where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
            .values(suppression_state="proposed", updated_at=func.now())
        )
        return "proposed"
    return None


def approve_suppression(
    db: Session, tenant_key: str, fingerprint_key: str, expiry_days: int = SUPPRESSION_EXPIRY_DAYS,
) -> datetime.datetime:
    """proposed -> active, with an expiry. Admin-only is enforced by the
    route's RBAC dependency, not here. Raises InvalidSuppressionTransition
    if the fingerprint isn't currently 'proposed' - this is never a
    shortcut from 'none' straight to 'active'."""
    fp_row = db.execute(
        select(fingerprints).where(
            fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key
        )
    ).mappings().first()
    if fp_row is None:
        raise FingerprintNotFound(fingerprint_key)
    if fp_row["suppression_state"] != "proposed":
        raise InvalidSuppressionTransition(
            f"cannot activate suppression from state {fp_row['suppression_state']!r} - must be 'proposed'"
        )

    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=expiry_days)
    db.execute(
        fingerprints.update()
        .where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
        .values(suppression_state="active", suppression_expires_at=expires_at, updated_at=func.now())
    )
    db.commit()
    return expires_at


def effective_suppression_state(db: Session, tenant_key: str, fingerprint_key: str) -> tuple[str, bool]:
    """Reads the fingerprint's suppression state, lazily downgrading an
    expired 'active' back to 'proposed' and persisting that downgrade (a
    real state change the caller should audit, not just a read-time
    illusion). Returns (state, did_expire_just_now)."""
    fp_row = db.execute(
        select(fingerprints).where(
            fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key
        )
    ).mappings().first()
    if fp_row is None:
        return "none", False

    if fp_row["suppression_state"] == "active" and fp_row["suppression_expires_at"] is not None:
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = fp_row["suppression_expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if expires_at <= now:
            db.execute(
                fingerprints.update()
                .where(fingerprints.c.tenant_key == tenant_key, fingerprints.c.fingerprint_key == fingerprint_key)
                .values(suppression_state="proposed", suppression_expires_at=None, updated_at=func.now())
            )
            db.commit()
            return "proposed", True

    return fp_row["suppression_state"], False
