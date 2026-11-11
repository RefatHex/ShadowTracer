"""6.5 A3: KEV/EPSS enrichment tags incidents whose alerts mention a CVE (DB integration)."""
import datetime
import json
import urllib.parse

from sqlalchemy import text

from app.models import incident_alerts, incidents
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "intel"))
from shadowtracer_intel import cve_enrich  # noqa: E402
from test_incidents_api import _make_incident, app_settings, client, tenant  # noqa: F401
# `db` and `engine` are conftest fixtures (no import needed)


class _FakeCH:
    def __init__(self, mentions):
        self._mentions = mentions      # [(node, alert_id, [cves])]
    def query(self, sql, parameters=None, settings=None):
        import types
        return types.SimpleNamespace(result_rows=self._mentions)


def _epss_http(url, timeout=60):
    cves = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["cve"][0].split(",")
    return json.dumps({"data": [{"cve": c, "epss": "0.9" if "34527" in c else "0.02",
                                 "percentile": "0.99", "date": "2026-11-11"} for c in cves]}).encode()


def test_tag_incidents_sets_kev_epss_and_floors_priority(db, engine, tenant):
    tid, t = tenant
    now = datetime.datetime.now(datetime.timezone.utc)
    # KEV catalogue has the PrintNightmare CVE; the other CVE is not exploited
    db.execute(text("INSERT INTO kev_vulnerabilities (cve_id, product, known_ransomware) "
                    "VALUES ('CVE-2021-34527','Windows',true)"))
    inc = _make_incident(db, t, agent_id="002")      # max_level 5 -> baseline priority 5
    db.execute(incident_alerts.insert().values(incident_id=inc, tenant_key=t, node="worker-test",
                                               alert_id="a1", alert_time=now))
    db.commit()
    ch = _FakeCH([("worker-test", "a1", ["CVE-2021-34527", "CVE-2099-0001"])])

    out = cve_enrich.tag_incidents(engine, ch, t, now=now, http=_epss_http)
    assert out["incidents"] == 1 and out["kev"] == 1
    row = db.execute(incidents.select().where(incidents.c.id == inc)).mappings().one()
    assert set(row["cve_ids"]) == {"CVE-2021-34527", "CVE-2099-0001"}
    assert row["kev_cve_ids"] == ["CVE-2021-34527"]
    assert abs(row["max_epss"] - 0.9) < 1e-6
    assert row["priority"] == 13                      # floored because a KEV CVE is present
    assert row["cve_enriched_at"] is not None
    # EPSS stored for both
    assert db.execute(text("SELECT count(*) FROM epss_scores")).scalar_one() == 2


def test_no_mentions_is_a_noop(db, engine, tenant):
    _, t = tenant
    out = cve_enrich.tag_incidents(engine, _FakeCH([]), t, http=_epss_http)
    assert out == {"incidents": 0, "cves": 0}
