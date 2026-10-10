"""The closer's continuous loop - polls close_eligible_incidents on an
interval until told to stop. Separate from closer.py's one-shot function
so that function stays simple to call directly from a test (or a one-off
admin script) without spinning up a thread.
"""

import logging
import time

import clickhouse_connect
from sqlalchemy.orm import Session, sessionmaker

from .closer import close_eligible_incidents

logger = logging.getLogger(__name__)


def run(
    database_url: str,
    clickhouse_host: str,
    clickhouse_port: int,
    clickhouse_user: str,
    clickhouse_password: str,
    clickhouse_database: str,
    session_gap_seconds: int,
    internal_ranges: list[str],
    metrics,
    stop_flag,
    poll_interval_seconds: float = 30.0,
    started_flag=None,
):
    from sqlalchemy import create_engine

    engine = create_engine(database_url, pool_pre_ping=True)
    Session_ = sessionmaker(bind=engine, expire_on_commit=False)

    if started_flag is not None:
        started_flag.set()

    while not stop_flag.is_set():
        db: Session = Session_()
        # ch_client construction used to happen outside this try - a
        # transient ClickHouse hiccup (e.g. the startup race in
        # PHASE5C_SIGMA.md §11: "started" but not yet ready to serve
        # queries) raised here, uncaught, and killed the whole process
        # instead of just this cycle. The poll loop already provides the
        # retry cadence; no backoff helper needed, just don't let this
        # escape the cycle it belongs to.
        ch_client = None
        try:
            ch_client = clickhouse_connect.get_client(
                host=clickhouse_host, port=clickhouse_port,
                username=clickhouse_user, password=clickhouse_password,
            )
            closed = close_eligible_incidents(
                db, ch_client, clickhouse_database, session_gap_seconds, internal_ranges,
            )
            metrics.incr("incidents_closed", by=len(closed))
        except Exception:
            logger.exception("close_eligible_incidents failed this cycle")
            metrics.incr("close_cycle_errors")
        finally:
            if ch_client is not None:
                ch_client.close()
            db.close()

        stop_flag.wait(poll_interval_seconds)
