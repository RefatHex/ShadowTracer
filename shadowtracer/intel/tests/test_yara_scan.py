"""YARA-X active-response scan script safety (Phase 6.5 A2): path confinement, re-hash, no shell."""
import importlib.machinery
import importlib.util
import os

_path = os.path.join(os.path.dirname(__file__), "..", "active_response", "shadowtracer-yara-scan")
_loader = importlib.machinery.SourceFileLoader("st_yara_scan", _path)
ys = importlib.util.module_from_spec(importlib.util.spec_from_loader("st_yara_scan", _loader))
_loader.exec_module(ys)


def test_extract_target_from_syscheck_and_data():
    assert ys.extract_target({"parameters": {"alert": {"syscheck": {"path": "/etc/x", "sha256_after": "AB"}}}}) == ("/etc/x", "ab")
    assert ys.extract_target({"alert": {"data": {"shadowtracer_scan_path": "/tmp/y", "shadowtracer_scan_sha256": "cd"}}}) == ("/tmp/y", "cd")
    assert ys.extract_target({}) == (None, None)


def test_in_fim_dir_allows_monitored_rejects_outside():
    assert ys.in_fim_dir("/etc/passwd", fim_dirs=("/etc", "/usr/bin"))
    assert ys.in_fim_dir("/usr/bin/ls", fim_dirs=("/etc", "/usr/bin"))
    assert not ys.in_fim_dir("/root/secret", fim_dirs=("/etc", "/usr/bin"))
    assert not ys.in_fim_dir("relative/path", fim_dirs=("/etc",))
    assert not ys.in_fim_dir("", fim_dirs=("/etc",))
    # a prefix that is not a directory boundary must not match (/etc-evil vs /etc)
    assert not ys.in_fim_dir("/etc-evil/x", fim_dirs=("/etc",))


def test_symlink_escape_is_refused(tmp_path):
    fim = tmp_path / "fim"
    outside = tmp_path / "outside"
    fim.mkdir(); outside.mkdir()
    (outside / "secret").write_text("secret")
    link = fim / "link"
    link.symlink_to(outside / "secret")                 # a symlink inside the FIM dir -> outside it
    dirs = (os.path.realpath(str(fim)),)
    assert not ys.in_fim_dir(str(link), fim_dirs=dirs)   # resolves outside -> refused
    (fim / "real").write_text("ok")
    assert ys.in_fim_dir(str(fim / "real"), fim_dirs=dirs)


def test_crafted_filename_is_passed_as_one_argument_never_a_shell(tmp_path, monkeypatch):
    # a file whose NAME contains shell metacharacters, inside the FIM dir
    name = "evil; rm -rf . && $(whoami) `id` '\"\\ .sh"
    (tmp_path / name).write_text("x")
    monkeypatch.setattr(ys, "FIM_DIRS", (os.path.realpath(str(tmp_path)),))
    seen = {}

    def fake_scan(p):
        seen["path"] = p
        return []
    r = ys.evaluate({"alert": {"data": {"shadowtracer_scan_path": str(tmp_path / name)}}},
                    scanner=fake_scan, hasher=lambda p: "deadbeef")
    assert r["status"] == "no_match" and seen["path"] == str(tmp_path / name)   # exact path, no shell mangling


def test_evaluate_rehash_states():
    ar = {"alert": {"data": {"shadowtracer_scan_path": "/etc/x", "shadowtracer_scan_sha256": "expected"}}}
    monkey = {"FIM_DIRS": ("/etc",)}
    ys.FIM_DIRS = monkey["FIM_DIRS"]
    assert ys.evaluate(ar, scanner=lambda p: [], hasher=lambda p: None)["status"] == "gone"
    assert ys.evaluate(ar, scanner=lambda p: [], hasher=lambda p: "different")["status"] == "changed"
    assert ys.evaluate(ar, scanner=lambda p: [], hasher=lambda p: "expected")["status"] == "no_match"
    m = ys.evaluate(ar, scanner=lambda p: [{"rule": "eicar", "author": "ST", "tags": ["malware"]}],
                    hasher=lambda p: "expected")
    assert m["status"] == "match" and m["matches"][0]["author"] == "ST" and "DRL" in m["attribution"]


def test_path_outside_fim_is_refused_before_hashing():
    ys.FIM_DIRS = ("/etc",)
    called = []
    r = ys.evaluate({"alert": {"data": {"shadowtracer_scan_path": "/root/secret"}}},
                    scanner=lambda p: called.append(p) or [], hasher=lambda p: called.append(p) or "x")
    assert r["status"] == "refused" and called == []    # neither hashed nor scanned


def test_emit_lines_one_flat_line_per_match():
    import json
    r = {"status": "match", "path": "/tmp/x", "sha256": "ab", "scanned_at": "T", "attribution": "DRL 1.1 / GPL-2",
         "matches": [{"rule": "r1", "author": "A", "tags": ["malware", "apt"], "description": "d"},
                     {"rule": "r2", "author": None, "tags": [], "description": ""}]}
    objs = [json.loads(x) for x in ys.emit_lines(r)]
    assert len(objs) == 2 and objs[0]["yara_rule"] == "r1" and objs[0]["yara_author"] == "A"
    assert objs[0]["yara_tags"] == "malware,apt" and objs[1]["yara_author"] == "unknown"
    assert all(o["integration"] == "shadowtracer-yara" and o["status"] == "match" for o in objs)


def test_emit_lines_status_only_when_no_match():
    import json
    o = json.loads(ys.emit_lines({"status": "no_match", "path": "/usr/bin/ls", "sha256": "ab", "scanned_at": "T"})[0])
    assert o["status"] == "no_match" and "yara_rule" not in o
