"""Phase 7.7: a minimal OpenSearch "indexer" shim for Wazuh 4.14.8's vulnerability-detector.

In 4.14.8 the vulnerability scanner writes the full CVE inventory only to the Wazuh indexer's
states index (wazuh-states-vulnerabilities-<cluster>), never to alerts.json - only real-time
deltas alert. ShadowTracer runs no OpenSearch, so that inventory never lands anywhere. This shim
stands in for the indexer: it answers the exact OpenSearch HTTP subset the indexer-connector uses
(health, template/index bootstrap, _bulk, _search scroll, _delete_by_query) and turns every
indexed ECS vuln document into a row in ClickHouse vulnerability_states. Point a manager's
<indexer><host> at it (http, basic auth) and the queued CVE state flows in.

Only the subset the connector actually calls is implemented; everything else returns a benign 200.
The connector verified against: src/shared_modules/indexer_connector/src/indexerConnector.cpp and
monitoring.hpp. ponytail: stdlib http.server + one worker thread per request is plenty for one
manager pushing a periodic scan; swap for a real ASGI server only if many managers push at once.
"""
import base64
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import clickhouse_connect

log = logging.getLogger("vulnshim")

INDEX_PREFIX = "wazuh-states-vulnerabilities-"
_ISO = re.compile(r"[zZ]$")


def _parse_dt(value) -> datetime:
    """ECS detected_at is ISO8601 (may end in Z); fall back to now() on anything odd."""
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(_ISO.sub("+00:00", value)).astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _num(value) -> float:
    """cvss score.base is a number, or a fillEmptyOrNegative sentinel (-1 / '-') when unknown."""
    try:
        f = float(value)
        return f if f >= 0 else 0.0
    except (TypeError, ValueError):
        return 0.0


class VulnStore:
    """Writes vulnerability_states in ClickHouse. One client, guarded by a lock (the handler runs
    on many threads). first_seen is preserved across re-scans; deletes write a soft-delete tombstone
    that ReplacingMergeTree(last_seen, is_deleted) collapses onto the live row."""

    COLS = ["tenant_id", "agent_id", "agent_name", "package_name", "package_version", "cve_id",
            "severity", "cvss_score", "detected_at", "first_seen", "last_seen", "doc_id", "is_deleted"]

    def __init__(self, client, database: str, tenant_map: dict):
        self._client = client
        self._db = database
        self._tenant_map = tenant_map
        self._lock = threading.Lock()

    def tenant_for_index(self, index: str):
        """wazuh-states-vulnerabilities-<cluster> -> tenant. Unknown cluster -> None (rows dropped);
        tenant isolation is a trust boundary, never guessed."""
        if not index.startswith(INDEX_PREFIX):
            return None
        return self._tenant_map.get(index[len(INDEX_PREFIX):])

    def _first_seen(self, tenant: str, doc_ids: list) -> dict:
        if not doc_ids:
            return {}
        rows = self._client.query(
            f"SELECT doc_id, min(first_seen) FROM {self._db}.vulnerability_states "
            "WHERE tenant_id = {t:String} AND doc_id IN {ids:Array(String)} GROUP BY doc_id",
            parameters={"t": tenant, "ids": doc_ids}).result_rows
        return {r[0]: r[1] for r in rows}

    def apply(self, index_ops: list, delete_ids: list) -> None:
        """index_ops: list of (tenant, doc_id, ecs_doc). delete_ids: list of (tenant, doc_id)."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._lock:
            rows = []
            by_tenant: dict = {}
            for tenant, doc_id, _ in index_ops:
                by_tenant.setdefault(tenant, []).append(doc_id)
            seen = {t: self._first_seen(t, ids) for t, ids in by_tenant.items()}
            for tenant, doc_id, doc in index_ops:
                agent = doc.get("agent") or {}
                pkg = doc.get("package") or {}
                vuln = doc.get("vulnerability") or {}
                rows.append([
                    tenant, str(agent.get("id", "")), str(agent.get("name", "")),
                    str(pkg.get("name", "")), str(pkg.get("version", "")), str(vuln.get("id", "")),
                    str(vuln.get("severity", "")), _num((vuln.get("score") or {}).get("base")),
                    _parse_dt(vuln.get("detected_at")), seen[tenant].get(doc_id, now), now, doc_id, 0,
                ])
            for tenant, doc_id in delete_ids:
                rows.append([tenant, "", "", "", "", "", "", 0.0, now, now, now, doc_id, 1])
            if rows:
                self._client.insert(f"{self._db}.vulnerability_states", rows, column_names=self.COLS)

    def delete_by_agents(self, tenant: str, agent_ids: list) -> int:
        """DELETED_BY_QUERY: soft-delete every live row of these agents by re-inserting them with
        is_deleted=1 and a newer last_seen."""
        if not agent_ids:
            return 0
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._lock:
            live = self._client.query(
                f"SELECT agent_id, agent_name, package_name, package_version, cve_id, severity, "
                f"cvss_score, detected_at, first_seen, doc_id FROM {self._db}.vulnerability_states FINAL "
                "WHERE tenant_id = {t:String} AND agent_id IN {a:Array(String)} AND is_deleted = 0",
                parameters={"t": tenant, "a": [str(a) for a in agent_ids]}).result_rows
            rows = [[tenant, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], now, r[9], 1] for r in live]
            if rows:
                self._client.insert(f"{self._db}.vulnerability_states", rows, column_names=self.COLS)
            return len(rows)


def _parse_bulk(body: str, store: VulnStore):
    """OpenSearch _bulk NDJSON -> (index_ops, delete_ids), tenant resolved from each line's _index."""
    index_ops, delete_ids, lines, i = [], [], body.split("\n"), 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line:
            continue
        try:
            action = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "index" in action or "create" in action:
            meta = action.get("index") or action.get("create")
            doc = json.loads(lines[i]) if i < len(lines) else {}
            i += 1
            tenant = store.tenant_for_index(meta.get("_index", ""))
            if tenant:
                index_ops.append((tenant, meta.get("_id", ""), doc))
        elif "delete" in action:
            meta = action["delete"]
            tenant = store.tenant_for_index(meta.get("_index", ""))
            if tenant:
                delete_ids.append((tenant, meta.get("_id", "")))
        elif "update" in action:  # not emitted by the vuln connector, but skip its doc line cleanly
            i += 1
    return index_ops, delete_ids


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # set by serve()
    store: VulnStore = None
    auth_header: str = None
    templates: dict = {}

    def log_message(self, *args):  # quiet; we log what matters ourselves
        pass

    def _send(self, code: int, obj):
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _authed(self) -> bool:
        if not self.auth_header:
            return True
        if self.headers.get("Authorization") == self.auth_header:
            return True
        self._send(401, {"error": {"type": "security_exception", "reason": "unauthorized"}})
        return False

    def _body(self) -> str:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def _index_from_path(self) -> str:
        return self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/_cat/health":  # unauthenticated, so the container healthcheck can hit it too
            return self._send(200, [{"status": "green", "cluster": "shadowtracer-shim"}])
        if not self._authed():
            return
        if path.endswith("/_mapping"):
            idx = self._index_from_path()
            mappings = self.templates.get(idx, {})
            return self._send(200, {idx: {"mappings": mappings}})
        if path.endswith("/_settings"):
            idx = self._index_from_path()
            return self._send(200, {idx: {"settings": {"index": {"number_of_shards": "1", "number_of_replicas": "0"}}}})
        if path.startswith("/_cat/indices"):
            return self._send(200, [])
        return self._send(200, {})

    def do_PUT(self):
        if not self._authed():
            return
        body = self._body()
        path = self.path.split("?", 1)[0]
        if path.startswith("/_index_template/"):
            # capture the template's mappings so GET /<idx>/_mapping matches its hash (skips reindex)
            try:
                tpl = json.loads(body)
                idx = path.rsplit("/", 1)[-1].removesuffix("_template")
                self.templates[idx] = (tpl.get("template") or {}).get("mappings", {})
            except (json.JSONDecodeError, AttributeError):
                pass
        return self._send(200, {"acknowledged": True})

    def do_POST(self):
        if not self._authed():
            return
        body = self._body()
        path = self.path.split("?", 1)[0]
        if path == "/_bulk":
            index_ops, delete_ids = _parse_bulk(body, self.store)
            try:
                self.store.apply(index_ops, delete_ids)
            except Exception:  # never crash the connector's sync loop; it retries
                log.exception("bulk apply failed")
                return self._send(200, {"took": 0, "errors": True, "items": []})
            if index_ops or delete_ids:
                log.info("bulk: %d indexed, %d deleted", len(index_ops), len(delete_ids))
            return self._send(200, {"took": 0, "errors": False, "items": []})
        if path.endswith("/_delete_by_query"):
            idx = self._index_from_path()
            tenant = self.store.tenant_for_index(idx)
            agents = []
            try:
                q = json.loads(body)
                agents = q["query"]["bool"]["filter"]["terms"]["agent.id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
            deleted = self.store.delete_by_agents(tenant, agents) if tenant else 0
            return self._send(200, {"deleted": deleted, "failures": []})
        if path.endswith("/_search") or path == "/_search/scroll":
            # reconciliation read: empty result set is safe (no spurious deletes)
            return self._send(200, {"_scroll_id": "shim", "hits": {"total": {"value": 0}, "hits": []}})
        return self._send(200, {})

    def do_DELETE(self):
        if not self._authed():
            return
        self._body()
        return self._send(200, {"acknowledged": True})


def serve():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    host, port = os.environ.get("CLICKHOUSE_HOSTS", "127.0.0.1:8123").split(",")[0].split(":")
    client = clickhouse_connect.get_client(
        host=host, port=int(port), username=os.environ["CLICKHOUSE_USER"],
        password=os.environ["CLICKHOUSE_PASSWORD"],
        database=os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"))
    tenant_map = json.loads(os.environ.get("VULN_TENANT_MAP", "{}"))
    if not tenant_map:
        raise SystemExit("VULN_TENANT_MAP is required (JSON {cluster-name: tenant-key})")

    user = os.environ.get("VULN_SHIM_USER", "admin")
    pw = os.environ.get("VULN_SHIM_PASSWORD", "admin")
    Handler.auth_header = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    Handler.store = VulnStore(client, os.environ.get("CLICKHOUSE_DATABASE", "shadowtracer"), tenant_map)
    Handler.templates = {}

    bind = int(os.environ.get("VULN_SHIM_PORT", "9200"))
    log.info("vuln-shim on :%d, tenants=%s", bind, list(tenant_map))
    ThreadingHTTPServer(("0.0.0.0", bind), Handler).serve_forever()


if __name__ == "__main__":
    serve()
