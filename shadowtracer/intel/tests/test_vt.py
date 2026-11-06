"""6.3 VirusTotal: report parsing, statuses, event shape, spool shell commands, manager script."""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys

import pytest

from shadowtracer_intel import safe_reload, vt

NOW = dt.datetime(2026, 11, 6, 12, tzinfo=dt.timezone.utc)
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
HERE = os.path.dirname(__file__)
# Shape of GET /api/v3/files/{id} (docs.virustotal.com/reference/file-info), trimmed.
REPORT = {"data": {"id": EICAR, "type": "file", "attributes": {
    "md5": "44d88612fea8a8f36de82e1278abb02f", "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
    "first_submission_date": 1148301722, "last_analysis_date": 1793900000,
    "last_analysis_stats": {"malicious": 62, "suspicious": 0, "undetected": 8, "harmless": 0, "timeout": 1, "type-unsupported": 5},
    "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"},
    "last_analysis_results": {
        "A": {"category": "malicious", "result": "EICAR-Test-File"}, "B": {"category": "malicious", "result": "EICAR-Test-File"},
        "C": {"category": "malicious", "result": "Eicar-Signature"}, "D": {"category": "undetected", "result": None}}}}}


def http(status, body=b"{}"):
    calls = []

    def get(url, headers, timeout=20):
        calls.append((url, headers))
        return status, body
    get.calls = calls
    return get


def test_malicious_report_parsed_with_labels_dates_link_and_ttl():
    get = http(200, json.dumps(REPORT).encode())
    v, status = vt.lookup(EICAR, "secret-key", NOW, get)
    assert status == 200 and get.calls[0][0] == f"https://www.virustotal.com/api/v3/files/{EICAR}"
    assert get.calls[0][1]["x-apikey"] == "secret-key"                       # header only, never the URL
    assert (v["status"], v["malicious"], v["total"]) == ("malicious", 62, 70)
    assert v["labels"] == ["virus.eicar/test", "EICAR-Test-File", "Eicar-Signature"]
    assert v["first_submission"].year == 2006 and v["last_analysis"] > v["first_submission"]
    assert v["permalink"] == f"https://www.virustotal.com/gui/file/{EICAR}"
    assert v["expires_at"] - NOW == dt.timedelta(days=30)


def test_clean_unknown_quota_and_errors_never_leak_the_key():
    clean = json.loads(json.dumps(REPORT))
    clean["data"]["attributes"]["last_analysis_stats"]["malicious"] = 0
    v, _ = vt.lookup(EICAR, "k", NOW, http(200, json.dumps(clean).encode()))
    assert v["status"] == "clean" and v["expires_at"] - NOW == dt.timedelta(days=7)
    v, status = vt.lookup(EICAR, "k", NOW, http(404))
    assert (v["status"], status, v["expires_at"] - NOW) == ("unknown", 404, dt.timedelta(days=7))
    with pytest.raises(vt.QuotaExceeded):
        vt.lookup(EICAR, "k", NOW, http(429))
    with pytest.raises(vt.VTError) as e:
        vt.lookup(EICAR, "super-secret-key", NOW, http(401))
    assert "super-secret-key" not in str(e.value)
    assert vt.key_fp("super-secret-key").startswith("vtkey-") and "secret" not in vt.key_fp("super-secret-key")


def test_event_is_wazuhs_virustotal_shape_and_queue_line():
    v, _ = vt.lookup(EICAR, "k", NOW, http(200, json.dumps(REPORT).encode()))
    req = {"alert_id": "1793.1", "path": "/var/ossec/lab-fim-test/eicar.com", "md5": "m", "sha1": "s",
           "agent_id": "002", "agent_name": "agent-ubuntu-1", "agent_ip": "any"}
    ev = vt.verdict_event(v, req, "api")
    assert ev["integration"] == "virustotal" and ev["virustotal"]["malicious"] == 1          # rule 87105
    assert ev["virustotal"]["source"] == {"alert_id": "1793.1", "file": "/var/ossec/lab-fim-test/eicar.com", "md5": "m", "sha1": "s"}
    assert ev["virustotal"]["positives"] == 62 and ev["virustotal"]["origin"] == "shadowtracer"  # rule 110100
    line = vt.queue_message(ev, req)
    assert line.startswith("1:[002] (agent-ubuntu-1) any->virustotal:{")
    assert json.loads(line.split("->virustotal:", 1)[1]) == ev
    assert vt.queue_message(ev, {**req, "agent_id": "000"}).startswith("1:virustotal:{")
    assert vt.confidence(v) == 90


class LocalNode(safe_reload.DockerNode):
    """The real spool shell commands, run locally against a temp install dir."""

    def _sh(self, script, stdin=None):
        res = subprocess.run(["sh", "-c", script], input=stdin, capture_output=True)
        assert res.returncode == 0, res.stderr
        return res.stdout


def test_manager_script_spools_and_node_takes_deletes_discards(tmp_path):
    integ = tmp_path / "integrations"
    integ.mkdir()
    shutil.copy(os.path.join(HERE, "..", "integrations", "custom-shadowtracer-virustotal.py"), integ)
    alert = {"id": "1793900000.123", "timestamp": "2026-11-06T12:00:00.000+0000", "rule": {"id": "554"},
             "agent": {"id": "002", "name": "agent-ubuntu-1", "ip": "any"}, "cluster": {"node": "worker-test"},
             "syscheck": {"path": "/x/eicar.com", "sha256_after": EICAR.upper(), "md5_after": "m", "sha1_after": "s"}}
    for i, a in enumerate([alert, {**alert, "id": "2.2"}, {**alert, "syscheck": {"path": "/gone", "event": "deleted"}}]):
        f = tmp_path / f"a{i}.alert"
        f.write_text(json.dumps(a))
        assert subprocess.run([sys.executable, str(integ / "custom-shadowtracer-virustotal.py"), str(f), "", ""]).returncode == 0
    node = LocalNode("worker-test", "unused", install_dir=str(tmp_path))
    taken = node.spool_take()
    assert len(taken) == 2                                                   # the deletion had no hash
    name, req = taken[0]
    assert req["sha256"] == EICAR and req["node"] == "worker-test" and req["agent"]["id"] == "002" and req["rule_id"] == "554"
    node.spool_delete([name, "../../etc/passwd"])                           # unsafe names ignored
    assert len(node.spool_take()) == 1
    assert node.spool_discard() == 1 and node.spool_take() == []
    assert LocalNode("x", "y", install_dir=str(tmp_path / "missing")).spool_take() == []
