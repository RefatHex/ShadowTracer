"""safe_reload.apply against fake manager nodes (6.1a item 3)."""
import hashlib

import pytest

from shadowtracer_intel import safe_reload, ti_rules

RULESET = {"ruleset/rules/0490-virustotal_rules.xml": [87100, 87105], "ruleset/rules/0015-ossec_rules.xml": [550, 554], "ruleset/rules/0045-firewall_rules.xml": [4100],
           "ruleset/rules/0095-sshd_rules.xml": [5700, 5710, 5715, 5722]}


def h(b):
    return hashlib.sha256(b).hexdigest()


class FakeNode:
    """warn_if(files) -> True makes analysisd warn. By default the staged validation
    (wazuh-analysisd -t) sees the same warning; validate_misses=True simulates a
    warning that only shows up on the live reload (the rollback path)."""
    def __init__(self, name, files=None, warn_if=None, validate_misses=False):
        self.name, self.files, self.warn_if, self.log = name, dict(files or {}), warn_if, []
        self.validate_misses = validate_misses

    def validate(self, bundle):
        self.log.append(("validate",))
        staged = dict(self.files, **bundle)
        bad = self.warn_if and self.warn_if(staged) and not self.validate_misses
        return ["(7616): List could not be loaded. Rule '110000' will be ignored."] if bad else []

    def read(self, p): return self.files.get(p)
    def write_atomic(self, p, d): self.log.append(("write", p)); self.files[p] = d
    def remove(self, p): self.log.append(("remove", p)); self.files.pop(p, None)
    def sha256(self, ps): return {p: (h(self.files[p]) if p in self.files else None) for p in ps}
    def ruleset_ids(self, exclude): return dict(RULESET)

    def reload(self):
        self.log.append(("reload", dict(self.files)))
        for p, d in list(self.files.items()):           # analysisd compiles every list
            if not p.endswith((".xml", ".cdb")):
                self.files[p + ".cdb"] = b"cdb:" + d
        bad = self.warn_if and self.warn_if(self.files)
        return {"success": True, "warnings": ["(7619): Rule dropped"] if bad else [], "errors": []}


class FakeWorker(FakeNode):
    """Receives the master's files only after `lag` checksum polls (the cluster's
    integrity sync), and refuses to reload with files that differ from the master's."""
    def __init__(self, name, master, lag=2, warn_if=None, validate_misses=False):
        super().__init__(name, dict(master.files), warn_if, validate_misses)
        self.master, self.lag, self.polls = master, lag, 0

    def sha256(self, ps):
        self.polls += 1
        if self.lag is not None and self.polls > self.lag:
            self.files = dict(self.master.files)
        return super().sha256(ps)

    def reload(self):
        assert self.files == self.master.files, "worker reloaded before its files matched the master's"
        return super().reload()


def reloads(node): return [e for e in node.log if e[0] == "reload"]


@pytest.fixture
def bundle(): return ti_rules.bundle()


def test_happy_path_workers_reload_only_after_their_checksums_match(bundle):
    m = FakeNode("master")
    w1, w2 = FakeWorker("worker1", m, lag=3), FakeWorker("worker2", m, lag=1)
    r = safe_reload.apply(m, [w1, w2], bundle, sync_timeout_s=5, poll_s=0)
    assert r.ok and [n.result for n in r.nodes] == ["ok", "ok", "ok"]
    assert len(reloads(m)) == 1 and len(reloads(w1)) == 1 and len(reloads(w2)) == 1
    # each worker's version equals the master's, including the compiled .cdb files
    assert r.nodes[1].versions == r.nodes[0].versions and any(p.endswith(".cdb") for p in r.nodes[0].versions)
    # rule file written after every list
    writes = [e[1] for e in m.log if e[0] == "write"]
    assert writes[-1] == ti_rules.RULES_FILE


def test_master_reload_warning_restores_previous_files(bundle):
    old = {ti_rules.RULES_FILE: b"<group name=\"old,\"></group>\n"}
    m = FakeNode("master", old, warn_if=lambda f: f.get(ti_rules.RULES_FILE) == bundle[ti_rules.RULES_FILE],
                 validate_misses=True)
    w = FakeWorker("worker1", m)
    r = safe_reload.apply(m, [w], bundle, sync_timeout_s=1, poll_s=0)
    assert not r.ok and r.nodes[0].result == "warnings"
    assert m.files[ti_rules.RULES_FILE] == old[ti_rules.RULES_FILE]                 # old rules back
    assert not any(p in m.files for p in ti_rules.list_paths())                     # new lists removed
    assert len(reloads(m)) == 2 and reloads(w) == []                                # rollback reload; worker untouched
    assert any("Rule dropped" in d for d in r.problems)


def test_bad_rule_file_is_rejected_before_anything_is_written(bundle):
    bundle[ti_rules.RULES_FILE] = (b'<group name="t,"><rule id="110000" level="5"><if_sid>5700</if_sid>'
                                   b'<list field="srcip" lookup="address_match_key_value">etc/lists/x</list>'
                                   b'<description>x</description></rule></group>')
    m = FakeNode("master")
    r = safe_reload.apply(m, [], bundle)
    assert not r.ok and r.nodes[0].result == "rejected" and m.log == []


@pytest.mark.parametrize("bad_node", ["master", "worker1"])
def test_staged_validation_warning_on_any_node_rejects_before_anything_is_written(bundle, bad_node):
    # The 6.1a rollback window: a bad file written to etc/ can reach a worker by
    # cluster sync and be loaded if that worker restarts. Validating on every node
    # first means a bad file is never written to the synced directories at all.
    is_new = lambda f: f.get(ti_rules.RULES_FILE) == bundle[ti_rules.RULES_FILE]
    m = FakeNode("master", warn_if=is_new if bad_node == "master" else None)
    w = FakeWorker("worker1", m, warn_if=is_new if bad_node == "worker1" else None)
    r = safe_reload.apply(m, [w], bundle, sync_timeout_s=1, poll_s=0)
    assert not r.ok and r.nodes[0].result == "rejected"
    assert any(p.startswith(bad_node + ":") and "will be ignored" in p for p in r.problems)
    assert [e for e in m.log if e[0] != "validate"] == [] and reloads(w) == []
    assert ti_rules.RULES_FILE not in m.files


def test_worker_that_never_syncs_is_not_reloaded(bundle):
    m = FakeNode("master")
    w = FakeWorker("worker1", m, lag=None)
    r = safe_reload.apply(m, [w], bundle, sync_timeout_s=0.05, poll_s=0.01)
    assert not r.ok and r.nodes[1].result == "sync_timeout" and reloads(w) == []
    assert r.nodes[0].result == "ok"


def test_worker_reload_warning_rolls_back_the_whole_cluster(bundle):
    old = {ti_rules.RULES_FILE: b"<group name=\"old,\"></group>\n"}
    m = FakeNode("master", old)
    w = FakeWorker("worker1", m, lag=0, warn_if=lambda f: f.get(ti_rules.RULES_FILE) == bundle[ti_rules.RULES_FILE],
                   validate_misses=True)
    r = safe_reload.apply(m, [w], bundle, sync_timeout_s=1, poll_s=0)
    assert not r.ok and r.nodes[0].result == "rolled_back" and r.nodes[1].result == "warnings"
    assert m.files[ti_rules.RULES_FILE] == old[ti_rules.RULES_FILE] and w.files[ti_rules.RULES_FILE] == old[ti_rules.RULES_FILE]
    assert len(reloads(m)) == 2 and len(reloads(w)) == 2


def test_unchanged_bundle_reloads_nothing(bundle):
    m = FakeNode("master")
    safe_reload.apply(m, [], bundle)
    m.log.clear()
    w = FakeWorker("worker1", m, lag=0)
    r = safe_reload.apply(m, [w], bundle, sync_timeout_s=1, poll_s=0)
    assert r.ok and [n.result for n in r.nodes] == ["unchanged", "unchanged"]
    assert reloads(m) == [] and reloads(w) == []
