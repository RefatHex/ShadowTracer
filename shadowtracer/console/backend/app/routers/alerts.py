"""Step 6's one API endpoint: recent alerts for the caller's tenant,
keyset-paginated. Deliberately never uses FINAL here - keyset pagination
lets a caller scroll arbitrarily far back, which makes this an unbounded
range by construction, and the console rule (PHASE3_DATA_PLATFORM.md) is
never FINAL over an unbounded range. An occasional duplicate row from an
unmerged part is an accepted tradeoff for this view, same as Phase 3's own
design philosophy - exact counts belong to the rollups/FINAL, not a
scrolling list.
"""

import datetime

import clickhouse_connect
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from ..config import Settings
from ..deps import get_settings
from ..rbac import ALL_ROLES, CurrentUser

router = APIRouter(prefix="/api", tags=["alerts"])

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

COLUMNS = [
    "time", "cluster_node", "alert_id", "agent_id", "agent_name",
    "rule_id", "rule_level", "rule_description", "message",
]


class Alert(BaseModel):
    time: datetime.datetime
    cluster_node: str
    alert_id: str
    agent_id: str
    agent_name: str
    rule_id: str
    rule_level: int
    rule_description: str
    message: str


class AlertsPage(BaseModel):
    alerts: list[Alert]
    next_cursor: str | None


def _get_ch_client(settings: Settings):
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host, port=settings.clickhouse_port,
        username=settings.clickhouse_user, password=settings.clickhouse_password,
        database=settings.clickhouse_database,
    )


def _encode_cursor(time: datetime.datetime, alert_id: str) -> str:
    return f"{time.isoformat()}|{alert_id}"


def _decode_cursor(cursor: str) -> tuple[str, str]:
    time_part, alert_id_part = cursor.split("|", 1)
    return time_part, alert_id_part


@router.get("/alerts", response_model=AlertsPage)
def recent_alerts(
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: str | None = None,
    settings: Settings = Depends(get_settings),
    current_user: CurrentUser = Depends(ALL_ROLES),
):
    # current_user.tenant_key is the tenant's permanent identity, carried
    # in the token itself and stamped onto every ClickHouse event by the
    # shipper - filtering with it directly needs no per-request Postgres
    # lookup, and is unaffected by the tenant's (display-only) name ever
    # changing.
    client = _get_ch_client(settings)
    try:
        where = ["tenant_id = {tenant_id:String}"]
        params = {"tenant_id": current_user.tenant_key, "limit": limit}

        if cursor:
            cursor_time, cursor_alert_id = _decode_cursor(cursor)
            where.append("(time, alert_id) < ({cursor_time:DateTime64(3)}, {cursor_alert_id:String})")
            params["cursor_time"] = cursor_time
            params["cursor_alert_id"] = cursor_alert_id

        query = f"""
            SELECT {', '.join(COLUMNS)}
            FROM events
            WHERE {' AND '.join(where)}
            ORDER BY time DESC, alert_id DESC
            LIMIT {{limit:UInt32}}
        """
        result = client.query(query, parameters=params)
        rows = result.result_rows

        alerts = [Alert(**dict(zip(COLUMNS, row))) for row in rows]
        next_cursor = _encode_cursor(alerts[-1].time, alerts[-1].alert_id) if len(alerts) == limit else None

        return AlertsPage(alerts=alerts, next_cursor=next_cursor)
    finally:
        client.close()
