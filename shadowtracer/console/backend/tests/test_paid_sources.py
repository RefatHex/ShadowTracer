"""Phase 6.5 B: tenant-managed paid-source key API - write-only, envelope-sealed, RBAC, audit."""
import os
from dataclasses import replace

from sqlalchemy import text

from app import secrets_crypto
from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401
# `db` is a conftest fixture (no import needed)

KEK = os.urandom(32)


def _with_kek(client):
    """Give the test app a KEK so paid-key management is enabled."""
    client.app.state.settings = replace(client.app.state.settings, key_encryption_key=KEK)
    return client


def _admin(client, db, tenant):
    return {"Authorization": f"Bearer {_token_for(client, db, tenant[0], 'a@x.io', role='admin')}"}


def test_list_defaults_all_sources_no_key(client, db, tenant):
    h = _admin(client, db, tenant)
    r = client.get("/api/ti/paid-sources", headers=h)
    assert r.status_code == 200
    body = {s["source"]: s for s in r.json()}
    assert set(body) == {"virustotal", "malwarebazaar", "abuseipdb", "greynoise"}
    assert all(not s["has_key"] and not s["enabled"] for s in body.values())
    assert body["virustotal"]["daily_budget"] == 500 and body["abuseipdb"]["cache_ttl_hours"] == 12


def test_set_key_is_write_only_and_envelope_sealed(client, db, tenant):
    _with_kek(client)
    h = _admin(client, db, tenant)
    r = client.put("/api/ti/paid-sources/virustotal",
                   json={"key": "VT-SECRET-wxyz", "enabled": True, "daily_budget": 250}, headers=h)
    assert r.status_code == 200, r.text
    s = r.json()
    # the response never contains the key, only fingerprint/last4
    assert "VT-SECRET-wxyz" not in r.text and "sealed_key" not in r.text
    assert s["has_key"] and s["enabled"] and s["key_last4"] == "wxyz" and s["key_version"] == 1
    assert s["key_fingerprint"] == secrets_crypto.fingerprint("VT-SECRET-wxyz")
    assert s["daily_budget"] == 250
    # the stored blob really decrypts to the key under the KEK (end-to-end envelope)
    blob = db.execute(text("SELECT sealed_key FROM tenant_source_keys WHERE tenant_key=:t AND source='virustotal'"),
                      {"t": tenant[1]}).scalar_one()
    assert "VT-SECRET-wxyz" not in blob            # at rest it is ciphertext, not the key
    assert secrets_crypto.open(KEK, tenant[1], "virustotal", blob) == "VT-SECRET-wxyz"
    # audited without the key value
    acts = [row[0] for row in db.execute(text("SELECT action FROM audit_log WHERE action LIKE 'paid_source%'"))]
    assert "paid_source_key_set" in acts
    tgt = db.execute(text("SELECT target FROM audit_log WHERE action='paid_source_key_set'")).scalar_one()
    assert "VT-SECRET-wxyz" not in tgt and "last4=wxyz" in tgt


def test_rotate_bumps_version(client, db, tenant):
    _with_kek(client); h = _admin(client, db, tenant)
    client.put("/api/ti/paid-sources/greynoise", json={"key": "gn-first-key", "enabled": True}, headers=h)
    r = client.put("/api/ti/paid-sources/greynoise", json={"key": "gn-second-key", "enabled": True}, headers=h)
    s = r.json()
    assert s["key_version"] == 2 and s["key_last4"] == "-key" and s["rotated_at"] is not None
    assert secrets_crypto.open(KEK, tenant[1], "greynoise",
            db.execute(text("SELECT sealed_key FROM tenant_source_keys WHERE tenant_key=:t AND source='greynoise'"),
                       {"t": tenant[1]}).scalar_one()) == "gn-second-key"


def test_enable_without_key_rejected(client, db, tenant):
    _with_kek(client); h = _admin(client, db, tenant)
    r = client.put("/api/ti/paid-sources/abuseipdb", json={"enabled": True}, headers=h)
    assert r.status_code == 409


def test_settings_only_change_without_key(client, db, tenant):
    _with_kek(client); h = _admin(client, db, tenant)
    r = client.put("/api/ti/paid-sources/malwarebazaar", json={"enabled": False, "daily_budget": 42}, headers=h)
    assert r.status_code == 200 and r.json()["daily_budget"] == 42 and not r.json()["has_key"]


def test_remove_key(client, db, tenant):
    _with_kek(client); h = _admin(client, db, tenant)
    client.put("/api/ti/paid-sources/virustotal", json={"key": "VT-SECRET-wxyz", "enabled": True}, headers=h)
    r = client.post("/api/ti/paid-sources/virustotal/remove", headers=h)
    assert r.status_code == 200 and not r.json()["has_key"] and not r.json()["enabled"]
    assert db.execute(text("SELECT sealed_key FROM tenant_source_keys WHERE tenant_key=:t AND source='virustotal'"),
                      {"t": tenant[1]}).scalar_one() is None
    assert client.post("/api/ti/paid-sources/virustotal/remove", headers=h).status_code == 404


def test_viewer_and_analyst_cannot_write(client, db, tenant):
    _with_kek(client)
    for role in ("viewer", "analyst"):
        h = {"Authorization": f"Bearer {_token_for(client, db, tenant[0], f'{role}@x.io', role=role)}"}
        assert client.put("/api/ti/paid-sources/virustotal", json={"key": "x" * 10}, headers=h).status_code == 403


def test_put_key_without_kek_configured_is_503(client, db, tenant):
    # default client has key_encryption_key=None
    h = _admin(client, db, tenant)
    r = client.put("/api/ti/paid-sources/virustotal", json={"key": "VT-SECRET-wxyz"}, headers=h)
    assert r.status_code == 503


def test_unknown_source_404(client, db, tenant):
    _with_kek(client); h = _admin(client, db, tenant)
    assert client.put("/api/ti/paid-sources/shodan", json={"key": "x" * 10}, headers=h).status_code == 404
