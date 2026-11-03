"""Phase 5.6 closeout, item 3: lets console-backend's /health endpoints
see a writer/correlator consumer stuck in a dead-letter retry-forever
loop - something Kafka's own consumer-group APIs can't distinguish
from ordinary lag, since both just look like "offsets not advancing"
from the outside. See component_retry_state's own migration docstring
(alembic/versions/9db37e0dcbaa_*.py) for the full rationale.
"""

import datetime
import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


def mark_stuck(engine, component: str, group_id: str, partitions_paused, error: str) -> None:
    """Upserts this component's retry-state row. stuck_since is set
    ONLY when the row doesn't already exist (the first attempt of a
    NEW stuck sequence) - a later attempt for the same still-unresolved
    retry only refreshes updated_at/last_error, so stuck_since keeps
    reflecting when this particular stuck sequence actually started,
    for computing how long it's been stuck.

    Never raises: this is a best-effort observability side-channel,
    same stance as dead_letter.py's own ClickHouse-insert half - a
    failure here (or a bug in it) must never be allowed to crash the
    actual retry loop it's reporting on. Confirmed the hard way: an
    earlier bug here raised from inside on_retry, which isn't wrapped
    in its own try/except by retry_with_backoff, and took the whole
    writer process down."""
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        # consumer.assignment() returns confluent_kafka.TopicPartition
        # objects (.topic/.partition attributes), not (topic, partition)
        # tuples.
        partitions_str = ",".join(f"{tp.topic}:{tp.partition}" for tp in partitions_paused)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO component_retry_state "
                    "(component, group_id, partitions_paused, stuck_since, updated_at, last_error) "
                    "VALUES (:component, :group_id, :partitions, :now, :now, :error) "
                    "ON CONFLICT (component) DO UPDATE SET "
                    "group_id = :group_id, partitions_paused = :partitions, "
                    "updated_at = :now, last_error = :error"
                ),
                {"component": component, "group_id": group_id, "partitions": partitions_str, "now": now, "error": error},
            )
    except Exception as exc:  # noqa: BLE001 - best-effort side-channel, see docstring
        logger.warning("mark_stuck failed (component=%s, non-fatal): %s", component, exc)


def clear_stuck(engine, component: str) -> None:
    """Deletes this component's row - called the moment a retry
    sequence succeeds, so a resolved retry disappears from /health/
    detail immediately rather than lingering until some TTL expires.
    Never raises - see mark_stuck's own docstring."""
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM component_retry_state WHERE component = :component"), {"component": component})
    except Exception as exc:  # noqa: BLE001 - best-effort side-channel, see mark_stuck's docstring
        logger.warning("clear_stuck failed (component=%s, non-fatal): %s", component, exc)
