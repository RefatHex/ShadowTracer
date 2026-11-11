"""Phase 6.5 A4: Tor exit node tag is context only - set on matching incidents, never changes priority."""
import datetime
import os
import sys
import uuid

from app.models import incidents, tenants
from test_incidents_api import app_settings, client, tenant  # noqa: F401

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "intel"))
from shadowtracer_intel import tor_exit  # noqa: E402


def test_tor_exit_tagging_is_context_only(db, engine):
    key = f"tor-{uuid.uuid4().hex[:8]}"
    db.execute(tenants.insert().values(name=key, tenant_key=key)); db.commit()
    torip, otherip = "171.25.193.25", "8.8.8.8"
    with engine.begin() as c:
        tor_exit.refresh(c, [torip])
    iid = db.execute(incidents.insert().values(
        tenant_key=key, correlation_key="c", correlation_basis="source_ip", agent_id="001",
        first_seen=datetime.datetime.now(datetime.timezone.utc), last_seen=datetime.datetime.now(datetime.timezone.utc),
        source_ips=[torip, otherip], source_ip_total=2, max_level=5).returning(incidents.c.id)).scalar_one()
    db.commit()
    before = db.execute(incidents.select().where(incidents.c.id == iid)).mappings().one()["priority"]
    with engine.begin() as c:
        tor_exit.tag_incidents(c)
    row = db.execute(incidents.select().where(incidents.c.id == iid)).mappings().one()
    assert list(row["tor_exit_ips"]) == [torip]          # only the Tor exit IP, not 8.8.8.8
    assert row["priority"] == before == 5                # context only: priority unchanged
