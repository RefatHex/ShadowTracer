"""Append-only audit log with a hash chain (Step 4). Each row's row_hash
covers its own fields AND the previous row's row_hash, so altering any
historical row (content or hash) breaks the chain from that point
forward - verify_chain() walks the whole table and names the first row
where the chain no longer adds up, whether that's a content edit (hash
mismatch) or a hash edit (linkage mismatch to the next row).

Appending takes SELECT ... FOR UPDATE on the last row to serialize
concurrent appends - without it, two concurrent writers could both read
the same "previous" hash and produce two rows claiming the same parent,
silently forking the chain.
"""

import datetime
import hashlib

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import audit_log

GENESIS_HASH = "0" * 64

# Arbitrary fixed key for a Postgres advisory lock, used to serialize
# concurrent appends (see append_entry). NOT `SELECT ... FOR UPDATE` on
# the last row - that requires UPDATE privilege on the table in Postgres
# even just to take the lock, which would mean granting the app role
# UPDATE on audit_log just to make appends safe, defeating the entire
# point of Step 4's append-only grant. An advisory lock needs no table
# privilege at all.
_APPEND_LOCK_KEY = 918_273_645


def _canonical(prev_hash: str, actor: str, tenant_id: int | None, action: str, target: str | None,
               outcome: str, created_at: datetime.datetime) -> str:
    return "|".join([
        prev_hash, actor, str(tenant_id), action, str(target), outcome,
        created_at.astimezone(datetime.timezone.utc).isoformat(),
    ])


def _compute_row_hash(*args, **kwargs) -> str:
    return hashlib.sha256(_canonical(*args, **kwargs).encode()).hexdigest()


def append_entry(
    db: Session, actor: str, tenant_id: int | None, action: str, target: str | None, outcome: str,
) -> None:
    # Transaction-scoped advisory lock: every appender must acquire this
    # exact lock before reading the tail and computing the next prev_hash,
    # serializing appends against each other without needing any extra
    # table privilege (see _APPEND_LOCK_KEY). Released automatically at
    # commit/rollback.
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _APPEND_LOCK_KEY})

    last_row = db.execute(
        select(audit_log).order_by(audit_log.c.id.desc()).limit(1)
    ).mappings().first()
    prev_hash = last_row["row_hash"] if last_row else GENESIS_HASH

    created_at = datetime.datetime.now(datetime.timezone.utc)
    row_hash = _compute_row_hash(prev_hash, actor, tenant_id, action, target, outcome, created_at)

    db.execute(
        audit_log.insert().values(
            actor=actor, tenant_id=tenant_id, action=action, target=target,
            created_at=created_at, outcome=outcome, prev_hash=prev_hash, row_hash=row_hash,
        )
    )
    db.commit()


class ChainVerificationResult:
    def __init__(self, valid: bool, first_broken_row_id: int | None, total_rows: int, reason: str | None = None):
        self.valid = valid
        self.first_broken_row_id = first_broken_row_id
        self.total_rows = total_rows
        self.reason = reason


def verify_chain(db: Session) -> ChainVerificationResult:
    rows = db.execute(select(audit_log).order_by(audit_log.c.id.asc())).mappings().all()
    expected_prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return ChainVerificationResult(
                valid=False, first_broken_row_id=row["id"], total_rows=len(rows),
                reason=f"row {row['id']}: prev_hash does not match the previous row's row_hash",
            )
        recomputed = _compute_row_hash(
            row["prev_hash"], row["actor"], row["tenant_id"], row["action"],
            row["target"], row["outcome"], row["created_at"],
        )
        if recomputed != row["row_hash"]:
            return ChainVerificationResult(
                valid=False, first_broken_row_id=row["id"], total_rows=len(rows),
                reason=f"row {row['id']}: stored row_hash does not match its own content "
                       f"(expected {recomputed}, got {row['row_hash']})",
            )
        expected_prev = row["row_hash"]

    return ChainVerificationResult(valid=True, first_broken_row_id=None, total_rows=len(rows))
