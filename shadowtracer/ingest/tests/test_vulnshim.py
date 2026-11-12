"""Phase 7.7: indexer-shim parsing + ClickHouse write logic. No live server/DB - a fake CH client
captures inserts. Covers bulk index/delete, tenant resolution from the index name, first_seen
preservation, delete-by-query, and the sentinel/odd-value coercions."""
from datetime import datetime

from shadowtracer_ingest.vulnshim import VulnStore, _parse_bulk, _parse_dt, _num


class FakeClient:
    def __init__(self, existing_first_seen=None, live_rows=None):
        self._fs = existing_first_seen or {}      # doc_id -> datetime
        self._live = live_rows or []              # rows for delete_by_agents
        self.inserts = []                         # (table, rows, cols)

    def query(self, sql, parameters=None):
        class R:
            pass
        r = R()
        if "min(first_seen)" in sql:
            ids = parameters["ids"]
            r.result_rows = [[d, self._fs[d]] for d in ids if d in self._fs]
        else:  # delete_by_agents live-row lookup
            r.result_rows = self._live
        return r

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


TENANTS = {"shadowtracer-test": "tenant-abc"}


def _store(client):
    return VulnStore(client, "shadowtracer", TENANTS)


def test_tenant_from_index():
    s = _store(FakeClient())
    assert s.tenant_for_index("wazuh-states-vulnerabilities-shadowtracer-test") == "tenant-abc"
    assert s.tenant_for_index("wazuh-states-vulnerabilities-unknown") is None   # isolation: never guess
    assert s.tenant_for_index("some-other-index") is None


def test_parse_bulk_index_and_delete():
    idx = "wazuh-states-vulnerabilities-shadowtracer-test"
    body = "\n".join([
        f'{{"index":{{"_index":"{idx}","_id":"d1"}}}}',
        '{"agent":{"id":"060","name":"ubuntu-1"},"package":{"name":"openssl","version":"1.1"},'
        '"vulnerability":{"id":"CVE-2024-1","severity":"High","score":{"base":7.5},"detected_at":"2026-11-12T00:00:00Z"}}',
        f'{{"delete":{{"_index":"{idx}","_id":"d2"}}}}',
        f'{{"index":{{"_index":"wazuh-states-vulnerabilities-unknown","_id":"x"}}}}',  # dropped: unknown tenant
        '{"agent":{"id":"999"}}',
        "",
    ])
    index_ops, delete_ids = _parse_bulk(body, _store(FakeClient()))
    assert [(t, i) for t, i, _ in index_ops] == [("tenant-abc", "d1")]
    assert delete_ids == [("tenant-abc", "d2")]


def test_apply_preserves_first_seen_and_fills_row():
    first = datetime(2026, 11, 1, 8, 0, 0)
    client = FakeClient(existing_first_seen={"d1": first})
    s = _store(client)
    doc = {"agent": {"id": "060", "name": "ubuntu-1"}, "package": {"name": "openssl", "version": "1.1"},
           "vulnerability": {"id": "CVE-2024-1", "severity": "High", "score": {"base": 7.5},
                             "detected_at": "2026-11-12T00:00:00Z"}}
    s.apply([("tenant-abc", "d1", doc)], [("tenant-abc", "d2")])
    table, rows, cols = client.inserts[0]
    assert table == "shadowtracer.vulnerability_states"
    by_doc = {r[cols.index("doc_id")]: r for r in rows}
    live, tomb = by_doc["d1"], by_doc["d2"]
    assert live[cols.index("first_seen")] == first          # preserved, not overwritten with now()
    assert live[cols.index("cve_id")] == "CVE-2024-1"
    assert live[cols.index("cvss_score")] == 7.5
    assert live[cols.index("is_deleted")] == 0
    assert tomb[cols.index("is_deleted")] == 1               # delete -> soft-delete tombstone


def test_delete_by_agents_tombstones_live_rows():
    now = datetime(2026, 11, 10, 0, 0, 0)
    # one live row for agent 060: (agent_id, name, pkg, ver, cve, sev, cvss, detected, first_seen, doc_id)
    live = [["060", "ubuntu-1", "openssl", "1.1", "CVE-2024-1", "High", 7.5, now, now, "d1"]]
    client = FakeClient(live_rows=live)
    n = _store(client).delete_by_agents("tenant-abc", ["060"])
    assert n == 1
    _, rows, cols = client.inserts[0]
    assert rows[0][cols.index("is_deleted")] == 1
    assert rows[0][cols.index("doc_id")] == "d1"
    assert rows[0][cols.index("cve_id")] == "CVE-2024-1"


def test_num_and_dt_coercions():
    assert _num(7.5) == 7.5
    assert _num(-1) == 0.0        # fillEmptyOrNegative sentinel
    assert _num("-") == 0.0
    assert _num(None) == 0.0
    assert _parse_dt("2026-11-12T00:00:00Z") == datetime(2026, 11, 12, 0, 0, 0)
    assert isinstance(_parse_dt("garbage"), datetime)   # falls back to now()
