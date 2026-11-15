"""Phase 7.8 demo: the Agents list endpoint. The Wazuh API client is monkeypatched (no manager
needed); this covers the happy path, the no-endpoint-configured empty state, and the degrade-on-API-
error empty state. Tenant scoping comes from the token."""
import uuid

import pytest
from app import wazuh_api

from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401


def _hdr(client, db, tenant, role="viewer"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


_FAKE = [{"id": "060", "name": "agent-ubuntu-1", "os": "Ubuntu", "status": "active",
          "last_seen": "2026-11-15T00:00:00+00:00", "manager": "worker-test", "ip": "172.28.0.21", "version": "v4.14.8"}]


def test_agents_listed_for_configured_tenant(client, db, tenant, monkeypatch):
    _tid, tkey = tenant
    monkeypatch.setattr(wazuh_api, "endpoints", lambda: {tkey: "https://mgr:55000"})
    monkeypatch.setattr(wazuh_api, "list_agents", lambda base: list(_FAKE))
    r = client.get("/api/agents", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["name"] == "agent-ubuntu-1" and body[0]["status"] == "active"
    assert body[0]["tenant"] == tkey      # tenant stamped from the token, not the API


def test_agents_empty_when_no_endpoint_configured(client, db, tenant, monkeypatch):
    monkeypatch.setattr(wazuh_api, "endpoints", lambda: {})   # this tenant has no manager API
    r = client.get("/api/agents", headers=_hdr(client, db, tenant))
    assert r.status_code == 200 and r.json() == []


def test_agents_empty_when_api_unreachable(client, db, tenant, monkeypatch):
    _tid, tkey = tenant
    monkeypatch.setattr(wazuh_api, "endpoints", lambda: {tkey: "https://mgr:55000"})

    def _boom(base):
        raise wazuh_api.WazuhApiError("connection refused")
    monkeypatch.setattr(wazuh_api, "list_agents", _boom)
    r = client.get("/api/agents", headers=_hdr(client, db, tenant))
    assert r.status_code == 200 and r.json() == []   # degrades to empty, never 500
