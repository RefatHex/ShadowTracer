"""Phase 7.8 demo: a tiny read-only client for the Wazuh manager API, used by the Agents page.

The lab runs one cluster per tenant, so a tenant's manager API lists exactly that tenant's agents.
Endpoints and credentials come from env (WAZUH_API_ENDPOINTS maps tenant_key -> base URL; a shared
WAZUH_API_USER/WAZUH_API_PASSWORD). The manager uses a self-signed cert on the lab network, so TLS
verification is off here - this talks only to the lab managers named in WAZUH_API_ENDPOINTS, never
to anything a tenant controls. Tokens are cached per base URL until they near expiry. Best-effort:
every call returns a value or raises WazuhApiError, and the router degrades to an empty list.
"""
import json
import os
import ssl
import time
import urllib.request

_TOKENS: dict[str, tuple[str, float]] = {}   # base_url -> (token, expires_at)
_TOKEN_TTL = 800                              # Wazuh tokens last 900s; refresh a bit early
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class WazuhApiError(RuntimeError):
    pass


def endpoints() -> dict[str, str]:
    """tenant_key -> manager API base URL, from WAZUH_API_ENDPOINTS (JSON). Empty if unset/bad."""
    try:
        return json.loads(os.environ.get("WAZUH_API_ENDPOINTS", "") or "{}")
    except json.JSONDecodeError:
        return {}


def _request(url: str, method: str = "GET", headers: dict | None = None, data: bytes | None = None):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=4, context=_CTX) as r:
            return json.loads(r.read().decode())
    except Exception as e:  # noqa: BLE001 - any network/parse failure is one degraded path
        raise WazuhApiError(str(e)) from e


def _token(base_url: str) -> str:
    cached = _TOKENS.get(base_url)
    if cached and cached[1] > time.time():
        return cached[0]
    user = os.environ.get("WAZUH_API_USER", "wazuh-wui")
    pw = os.environ.get("WAZUH_API_PASSWORD", "")
    if not pw:
        raise WazuhApiError("WAZUH_API_PASSWORD not set")
    import base64
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    body = _request(f"{base_url}/security/user/authenticate", method="POST",
                    headers={"Authorization": f"Basic {auth}"})
    token = body.get("data", {}).get("token")
    if not token:
        raise WazuhApiError("no token in authenticate response")
    _TOKENS[base_url] = (token, time.time() + _TOKEN_TTL)
    return token


def list_agents(base_url: str) -> list[dict]:
    """Return normalized agent dicts for one manager: id, name, os, status, last_seen, manager."""
    sel = "id,name,os.name,os.platform,status,lastKeepAlive,node_name,dateAdd,ip,version"
    body = _request(f"{base_url}/agents?limit=500&sort=id&select={sel}",
                    headers={"Authorization": f"Bearer {_token(base_url)}"})
    out = []
    for a in body.get("data", {}).get("affected_items", []):
        osd = a.get("os") or {}
        last = a.get("lastKeepAlive")
        # Wazuh uses a sentinel far-future keepalive for the manager (id 000); show it as "-"
        if last and last.startswith("9999"):
            last = None
        out.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "os": osd.get("name") or osd.get("platform") or "-",
            "status": a.get("status") or "unknown",
            "last_seen": last,
            "manager": a.get("node_name") or "-",
            "ip": a.get("ip"),
            "version": a.get("version"),
        })
    return out


def run_command(base_url: str, agent_id: str, script: str, arguments: list[str], srcip: str) -> None:
    """Dispatch a custom AR script (the !script form, which bypasses ar.conf command validation)
    to one agent via PUT /active-response. srcip is the AR active key; arguments become extra_args
    (e.g. ['add'] / ['delete'] for the ShadowTracer firewall script). Raises WazuhApiError if the
    manager reports the command was not sent to the agent. Phase 9 SOAR containment dispatch."""
    body = json.dumps({"command": f"!{script}", "arguments": arguments,
                       "alert": {"data": {"srcip": srcip}}}).encode()
    data = _request(
        f"{base_url}/active-response?agents_list={agent_id}", method="PUT",
        headers={"Authorization": f"Bearer {_token(base_url)}", "Content-Type": "application/json"},
        data=body)
    affected = data.get("data", {}).get("total_affected_items", 0)
    if affected < 1:
        failed = data.get("data", {}).get("failed_items")
        raise WazuhApiError(f"AR '{script}' not dispatched to agent {agent_id}: {failed}")
