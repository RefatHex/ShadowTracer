"""6.5 C: analyst-initiated IP lookups (AbuseIPDB/GreyNoise) - key/opt-in/budget/cache/audit."""
from sqlalchemy import text

from app import ip_sources, secrets_crypto
from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401
from test_paid_sources import KEK, _with_kek  # noqa: F401


def _enable(db, tenant, source, key_value, budget=None):
    sealed = secrets_crypto.seal(KEK, tenant[1], source, key_value)
    db.execute(text("INSERT INTO tenant_source_keys (tenant_key, source, enabled, sealed_key, key_fingerprint, "
                    "key_last4, key_version, daily_budget) VALUES (:t,:s,true,:b,:fp,:l4,1,:bud) "
                    "ON CONFLICT (tenant_key, source) DO UPDATE SET enabled=true, sealed_key=:b, daily_budget=:bud"),
               {"t": tenant[1], "s": source, "b": sealed, "fp": "fp", "l4": key_value[-4:], "bud": budget})
    db.commit()


def _hdr(client, db, tenant, role="analyst"):
    return {"Authorization": f"Bearer {_token_for(client, db, tenant[0], f'{role}@x.io', role=role)}"}


def test_abuseipdb_live_then_cache(client, db, tenant, monkeypatch):
    _with_kek(client)
    _enable(db, tenant, "abuseipdb", "ABUSE-KEY-9999")
    seen = {}
    def fake(ip, key, http=None):
        seen["key"] = key
        return {"source": "abuseipdb", "indicator": ip, "status": "malicious", "data": {"abuse_confidence_score": 90}}
    monkeypatch.setitem(ip_sources.LOOKUPS, "abuseipdb", fake)
    h = _hdr(client, db, tenant)
    r = client.post("/api/ti/ip-lookups", json={"ip": "1.2.3.4", "source": "abuseipdb"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "malicious" and r.json()["served_from"] == "live"
    assert seen["key"] == "ABUSE-KEY-9999"                 # the sealed key was decrypted with the KEK
    # cached on the second call: no new source_call
    calls = db.execute(text("SELECT count(*) FROM source_calls WHERE tenant_key=:t"), {"t": tenant[1]}).scalar_one()
    r2 = client.post("/api/ti/ip-lookups", json={"ip": "1.2.3.4", "source": "abuseipdb"}, headers=h)
    assert r2.json()["served_from"] == "cache"
    assert db.execute(text("SELECT count(*) FROM source_calls WHERE tenant_key=:t"), {"t": tenant[1]}).scalar_one() == calls
    # audited
    acts = [x[0] for x in db.execute(text("SELECT outcome FROM audit_log WHERE action='ip_lookup'"))]
    assert "ok:malicious" in acts and "cached" in acts


def test_greynoise_validates_ip_and_source(client, db, tenant):
    _with_kek(client)
    h = _hdr(client, db, tenant)
    assert client.post("/api/ti/ip-lookups", json={"ip": "not-an-ip", "source": "greynoise"}, headers=h).status_code == 422
    assert client.post("/api/ti/ip-lookups", json={"ip": "8.8.8.8", "source": "virustotal"}, headers=h).status_code == 404


def test_not_enabled_is_409(client, db, tenant):
    _with_kek(client)
    h = _hdr(client, db, tenant)
    assert client.post("/api/ti/ip-lookups", json={"ip": "9.9.9.9", "source": "greynoise"}, headers=h).status_code == 409


def test_budget_exhausted_is_429(client, db, tenant, monkeypatch):
    _with_kek(client)
    _enable(db, tenant, "abuseipdb", "K", budget=0)       # zero budget
    monkeypatch.setitem(ip_sources.LOOKUPS, "abuseipdb", lambda ip, key, http=None: {"status": "clean", "data": {}})
    h = _hdr(client, db, tenant)
    assert client.post("/api/ti/ip-lookups", json={"ip": "1.1.1.1", "source": "abuseipdb"}, headers=h).status_code == 429


def test_viewer_forbidden_and_no_kek_503(client, db, tenant):
    hv = _hdr(client, db, tenant, role="viewer")
    assert client.post("/api/ti/ip-lookups", json={"ip": "1.1.1.1", "source": "abuseipdb"}, headers=hv).status_code == 403
    # analyst but no KEK configured (default client) -> 503, after enabling a row so it reaches the KEK check
    _enable(db, tenant, "abuseipdb", "K")
    ha = _hdr(client, db, tenant)
    assert client.post("/api/ti/ip-lookups", json={"ip": "1.1.1.1", "source": "abuseipdb"}, headers=ha).status_code == 503


def test_ip_source_clients_parse_status():
    ab = ip_sources.abuseipdb_lookup("1.2.3.4", "k",
        http=lambda u, h, timeout=15: (200, b'{"data":{"abuseConfidenceScore":80,"totalReports":5}}'))
    assert ab["status"] == "malicious" and ab["data"]["total_reports"] == 5
    low = ip_sources.abuseipdb_lookup("1.2.3.4", "k", http=lambda u, h, timeout=15: (200, b'{"data":{"abuseConfidenceScore":0}}'))
    assert low["status"] == "clean"
    gn = ip_sources.greynoise_lookup("1.2.3.4", "k", http=lambda u, h, timeout=15: (404, b""))
    assert gn["status"] == "unknown"
    gm = ip_sources.greynoise_lookup("1.2.3.4", "k", http=lambda u, h, timeout=15: (200, b'{"classification":"malicious","noise":true}'))
    assert gm["status"] == "malicious"
