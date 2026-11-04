"""Opt-in per-batch time breakdown for the correlator consumer.

Off unless SHADOWTRACER_PROFILE_BATCHES=1; when off, nothing is hooked and
every call below is a no-op. When on, one JSON log line per batch:

  wall_s     the whole loop iteration
  phases     consume / prepare (per-message checks) / process (process_batch) / commit
  cpu_s      process CPU time (time.process_time) during process_batch - Python work,
             plus whatever librdkafka's own threads burned in that window
  db_s       time inside SQL round trips during process_batch (SQLAlchemy
             before/after_cursor_execute), split by statement kind in `sql`
  other_s    process - cpu - db: commit round trip, GIL waits, scheduling
"""

import json
import logging
import os
import time

from sqlalchemy import event

ENABLED = os.environ.get("SHADOWTRACER_PROFILE_BATCHES") == "1"
logger = logging.getLogger("shadowtracer_correlate.profile")


def _kind(statement: str) -> str:
    s = " ".join(statement.split()).lower()
    if s.startswith("select") and "from incident_alerts" in s:
        return "membership_lookup"
    if s.startswith("select") and "from incidents" in s and "for update" in s:
        return "incident_lock"
    if s.startswith("insert into incidents"):
        return "incident_insert"
    if s.startswith("insert into incident_alerts"):
        return "membership_insert"
    if s.startswith("update incidents"):
        return "incident_update"
    if "sequence_progress" in s:
        return "sequences"
    return "other"


class BatchProfiler:
    def __init__(self, engine):
        self._sql = {}
        if ENABLED:
            event.listen(engine, "before_cursor_execute", self._before)
            event.listen(engine, "after_cursor_execute", self._after)

    def _before(self, conn, cursor, statement, parameters, context, executemany):
        context._profile_start = time.perf_counter()

    def _after(self, conn, cursor, statement, parameters, context, executemany):
        kind = _kind(statement)
        n, secs = self._sql.get(kind, (0, 0.0))
        self._sql[kind] = (n + 1, secs + time.perf_counter() - context._profile_start)

    def start(self):
        if ENABLED:
            self._t0 = self._last = time.perf_counter()
            self._phases, self._sql = {}, {}

    def mark(self, phase: str):
        if ENABLED:
            now = time.perf_counter()
            self._phases[phase] = self._phases.get(phase, 0.0) + now - self._last
            self._last = now
            if phase == "prepare":
                self._cpu0 = time.process_time()
            elif phase == "process":
                self._cpu = time.process_time() - self._cpu0

    def emit(self, messages: int, alerts: int):
        if not ENABLED:
            return
        db = sum(s for _, s in self._sql.values())
        process = self._phases.get("process", 0.0)
        logger.info("batch_profile %s", json.dumps({
            "messages": messages, "alerts": alerts,
            "wall_s": round(time.perf_counter() - self._t0, 4),
            "phases": {k: round(v, 4) for k, v in self._phases.items()},
            "cpu_s": round(getattr(self, "_cpu", 0.0), 4),
            "db_s": round(db, 4),
            "other_s": round(process - db - getattr(self, "_cpu", 0.0), 4),
            "sql": {k: [n, round(s, 4)] for k, (n, s) in sorted(self._sql.items())},
        }))
