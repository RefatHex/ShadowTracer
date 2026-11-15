"""6.5 A3: KEV/EPSS parsing + EPSS batching (pure). DB enrichment is tested in the backend suite."""
import json
import urllib.parse

from shadowtracer_intel import cve_enrich


def test_parse_kev_keeps_valid_marks_ransomware():
    body = json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2021-34527", "vendorProject": "Microsoft", "product": "Windows",
         "vulnerabilityName": "PrintNightmare", "dateAdded": "2021-07-13", "dueDate": "2021-07-20",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "not-a-cve"}]}).encode()
    rows = cve_enrich.parse_kev(body)
    assert len(rows) == 1 and rows[0]["cve_id"] == "CVE-2021-34527"
    assert rows[0]["known_ransomware"] is True and rows[0]["product"] == "Windows"


def test_parse_epss():
    body = json.dumps({"data": [{"cve": "CVE-2021-34527", "epss": "0.97421", "percentile": "0.999", "date": "2026-11-11"}]}).encode()
    s = cve_enrich.parse_epss(body)
    assert s["CVE-2021-34527"][0] == 0.97421 and s["CVE-2021-34527"][1] == 0.999


def test_fetch_epss_batches_in_hundreds():
    cves = [f"CVE-2021-{i:04d}" for i in range(250)]
    calls = []

    def http(url, timeout=60):
        calls.append(url)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["cve"][0].split(",")
        return json.dumps({"data": [{"cve": c, "epss": "0.1", "percentile": "0.5", "date": "2026-11-11"} for c in q]}).encode()

    s = cve_enrich.fetch_epss(cves, http=http)
    assert len(s) == 250 and len(calls) == 3        # 100 + 100 + 50


def test_cve_regex_case_insensitive():
    found = cve_enrich.CVE_RE.findall("PrintNightmare CVE-2021-34527 and cve-2019-0708 and CVE-xx")
    assert found == ["CVE-2021-34527", "cve-2019-0708"]


def test_attribution_names_kev_and_epss():
    assert "KEV" in cve_enrich.ATTRIBUTION and "EPSS" in cve_enrich.ATTRIBUTION


# --- Phase 6.6: real EPSS enrichment of the vulnerability inventory ------------------------------
class _FakeCh:
    def __init__(self, cves):
        self._cves = cves

    def query(self, sql, parameters=None):
        class R:
            result_rows = [[c] for c in self._cves]
        return R()


class _FakeConn:
    def __init__(self, existing):
        self._existing = existing
        self.stored = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, stmt, params=None):
        text = str(stmt)
        if "SELECT cve_id FROM epss_scores" in text:
            return [(c,) for c in self._existing]
        self.stored.append(params)   # _epss_upsert
        return None


class _FakeEngine:
    def __init__(self, existing):
        self.read = _FakeConn(existing)
        self.write = _FakeConn(existing)

    def connect(self):
        return self.read

    def begin(self):
        return self.write


def test_vuln_state_cves_filters_to_valid_ids():
    ch = _FakeCh(["CVE-2026-84782", "not-a-cve", "cve-2026-35189", ""])
    assert cve_enrich.vuln_state_cves(ch, "t") == {"CVE-2026-84782", "CVE-2026-35189"}


def test_enrich_vuln_states_fetches_only_missing_epss():
    ch = _FakeCh(["CVE-2026-84782", "CVE-2026-35189"])
    engine = _FakeEngine(existing={"CVE-2026-84782"})          # one already has EPSS
    calls = []

    def http(url):
        calls.append(url)
        # EPSS API JSON for the one missing CVE
        return b'{"data":[{"cve":"CVE-2026-35189","epss":"0.0035","percentile":"0.29","date":"2026-11-14"}]}'

    r = cve_enrich.enrich_vuln_states(engine, ch, "t", http=http)
    assert r == {"cves": 2, "epss_fetched": 1}
    assert len(calls) == 1 and "CVE-2026-35189" in calls[0]      # only the missing one fetched
    assert engine.write.stored == [{"cve_id": "CVE-2026-35189", "epss": 0.0035, "percentile": 0.29, "scored_date": "2026-11-14"}]


def test_enrich_vuln_states_noop_when_no_inventory():
    assert cve_enrich.enrich_vuln_states(_FakeEngine(set()), _FakeCh([]), "t", http=lambda u: b"") == {"cves": 0, "epss_fetched": 0}
