"""Phase 7.7: the per-host / per-tenant vulnerability view - KEV-first + EPSS sort, enrichment,
tenant isolation, and resolved (is_deleted) rows excluded. Uses the real isolated CH + PG test DBs
(same harness as test_incidents_api)."""
import datetime
import uuid

from sqlalchemy import text

from test_incidents_api import _token_for, app_settings, client, ch_client, tenant  # noqa: F401

VS_COLS = ["tenant_id", "agent_id", "agent_name", "package_name", "package_version", "cve_id",
           "severity", "cvss_score", "detected_at", "first_seen", "last_seen", "doc_id", "is_deleted"]


def _vrow(tenant_key, agent_id, agent_name, pkg, ver, cve, sev, cvss, is_deleted=0):
    now = datetime.datetime(2026, 11, 12, 12, 0, 0)
    return [tenant_key, agent_id, agent_name, pkg, ver, cve, sev, cvss, now, now, now,
            f"{agent_id}-{cve}", is_deleted]


def _seed_kev(db, cve, ransomware=False):
    db.execute(text("INSERT INTO kev_vulnerabilities (cve_id, vulnerability_name, known_ransomware) "
                    "VALUES (:c, :n, :r) ON CONFLICT (cve_id) DO NOTHING"),
               {"c": cve, "n": f"{cve} exploited", "r": ransomware})
    db.commit()


def _seed_epss(db, cve, epss, pct):
    db.execute(text("INSERT INTO epss_scores (cve_id, epss, percentile) VALUES (:c, :e, :p) "
                    "ON CONFLICT (cve_id) DO NOTHING"), {"c": cve, "e": epss, "p": pct})
    db.commit()


def _hdr(client, db, tenant, role="viewer"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def test_hosts_sorted_kev_first_then_epss(client, db, ch_client, tenant):
    _tid, tkey = tenant
    m = uuid.uuid4().hex[:8]
    kev_cve, epss_cve, plain_cve = f"CVE-K-{m}", f"CVE-E-{m}", f"CVE-P-{m}"
    _seed_kev(db, kev_cve)
    _seed_epss(db, epss_cve, 0.80, 0.97)
    _seed_epss(db, kev_cve, 0.10, 0.5)
    ch_client.insert("vulnerability_states", [
        _vrow(tkey, f"hkev-{m}", "host-kev", "openssl", "1.1", kev_cve, "High", 7.5),
        _vrow(tkey, f"hepss-{m}", "host-epss", "zlib", "1.2", epss_cve, "Medium", 5.0),
        _vrow(tkey, f"hplain-{m}", "host-plain", "bash", "5.0", plain_cve, "Low", 2.0),
    ], column_names=VS_COLS)

    r = client.get("/api/vulnerabilities", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    hosts = [h for h in r.json() if h["agent_id"].endswith(m)]
    # KEV host first, then the high-EPSS host, then the plain one
    assert [h["agent_name"] for h in hosts] == ["host-kev", "host-epss", "host-plain"]
    assert hosts[0]["kev_count"] == 1 and hosts[0]["priority"] == "critical"
    assert hosts[1]["max_epss"] == 0.80


def test_host_cves_enriched_and_sorted(client, db, ch_client, tenant):
    _tid, tkey = tenant
    m = uuid.uuid4().hex[:8]
    kev_cve, epss_cve = f"CVE-K2-{m}", f"CVE-E2-{m}"
    _seed_kev(db, kev_cve, ransomware=True)
    _seed_epss(db, epss_cve, 0.6, 0.9)
    agent = f"host-{m}"
    ch_client.insert("vulnerability_states", [
        _vrow(tkey, agent, "web01", "openssl", "1.1", kev_cve, "High", 7.5),
        _vrow(tkey, agent, "web01", "zlib", "1.2", epss_cve, "Critical", 9.1),
    ], column_names=VS_COLS)

    r = client.get(f"/api/vulnerabilities/hosts/{agent}", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    rows = r.json()
    assert rows[0]["cve_id"] == kev_cve and rows[0]["kev"] and rows[0]["kev_ransomware"]  # KEV first
    assert rows[1]["cve_id"] == epss_cve and rows[1]["epss"] == 0.6


def test_resolved_rows_excluded(client, db, ch_client, tenant):
    _tid, tkey = tenant
    m = uuid.uuid4().hex[:8]
    agent = f"host-res-{m}"
    ch_client.insert("vulnerability_states", [
        _vrow(tkey, agent, "web01", "openssl", "1.1", f"CVE-LIVE-{m}", "High", 7.5, is_deleted=0),
        _vrow(tkey, agent, "web01", "zlib", "1.2", f"CVE-GONE-{m}", "High", 7.5, is_deleted=1),
    ], column_names=VS_COLS)
    r = client.get(f"/api/vulnerabilities/hosts/{agent}", headers=_hdr(client, db, tenant))
    assert [row["cve_id"] for row in r.json()] == [f"CVE-LIVE-{m}"]


def test_tenant_isolation(client, db, ch_client, tenant):
    _tid, tkey = tenant
    m = uuid.uuid4().hex[:8]
    ch_client.insert("vulnerability_states",
                     [_vrow(tkey, f"secret-{m}", "host", "p", "1", f"CVE-X-{m}", "High", 7.5)],
                     column_names=VS_COLS)
    # a brand-new, unrelated tenant must not see tkey's hosts
    other_key = f"key-other-{m}"
    other_id = db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :k) RETURNING id"),
                          {"n": f"other-{m}", "k": other_key}).scalar_one()
    db.commit()
    hdr = {"Authorization": f"Bearer {_token_for(client, db, other_id, f'o-{m}@x.io')}"}
    hosts = [h for h in client.get("/api/vulnerabilities", headers=hdr).json() if h["agent_id"].endswith(m)]
    assert hosts == []
