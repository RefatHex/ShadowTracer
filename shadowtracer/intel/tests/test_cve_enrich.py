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
