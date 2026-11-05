"""Distribute ShadowTracer TI files to ONE tenant's manager cluster and reload it safely.

THREAT_INTEL.md §4.4 / §4.12 / §4.16, 6.1a item 3:
1. Pre-flight: the TI rule file must load after every parent it names, and use no
   banned lookup (rule_order.check). Rejected bundles are never written.
2. Write every file on the master with write-temp-then-rename. `.tmp` files are
   excluded from cluster sync, so workers never see a half-written file.
3. Reload the master. ANY warning or error counts as failure (4.14.8 answers
   success=True while dropping rules, §9.2): the previous files go back and the
   master is reloaded again. The old lists and rules stay live.
4. A worker is reloaded only after the checksums of every TI file, and each list's
   compiled .cdb, equal the master's. Reloading earlier would load stale files and
   clear the cluster's reload flag (§1.7 race). Workers are reloaded directly, so
   their own warnings come back too. A worker reload with warnings rolls the whole
   cluster back.
5. Every node's version of every file and the result are recorded for /health/detail.

Transport: DockerNode runs commands in a lab container. In production the same five
calls are served by a small agent on each manager host (design §4.4). The logic below
only uses read/write_atomic/remove/sha256/reload/ruleset_ids.
"""
import hashlib
import io
import json
import re
import subprocess
import tarfile
import time
from dataclasses import dataclass, field

from . import rule_order

INSTALL_DIR = "/var/ossec"
_RELOAD_PY = """
import asyncio, json
from wazuh.core.analysis import send_reload_ruleset_msg
r = asyncio.run(send_reload_ruleset_msg(origin={'module': 'shadowtracer-ti'}))
print(json.dumps({'success': r.success, 'warnings': r.warnings, 'errors': r.errors}))
"""


class DockerNode:
    """A Wazuh manager node reached with `docker exec` (lab transport)."""

    def __init__(self, name: str, container: str, install_dir: str = INSTALL_DIR):
        self.name, self.container, self.install_dir = name, container, install_dir

    def _sh(self, script: str, stdin: bytes = None) -> bytes:
        res = subprocess.run(["docker", "exec", "-i", self.container, "sh", "-c", script],
                             input=stdin, capture_output=True)
        if res.returncode != 0:
            raise RuntimeError(f"{self.name}: {script[:60]!r} failed: {res.stderr.decode(errors='replace')[-500:]}")
        return res.stdout

    def _abs(self, rel: str) -> str:
        if rel.startswith("/") or ".." in rel.split("/") or "'" in rel:
            raise ValueError(f"unsafe path {rel!r}")
        return f"{self.install_dir}/{rel}"

    def read(self, rel: str):
        p = self._abs(rel)
        out = self._sh(f"if [ -f '{p}' ]; then printf 1; cat '{p}'; else printf 0; fi")
        return out[1:] if out[:1] == b"1" else None

    def write_atomic(self, rel: str, data: bytes) -> None:
        p = self._abs(rel)
        # A text list must be newer than its .cdb or analysisd will not recompile it
        # (lists_make.c:47-48 compares mtimes in whole seconds).
        self._sh(
            f"set -e; d=$(dirname '{p}'); mkdir -p \"$d\"; chown wazuh:wazuh \"$d\"; chmod 770 \"$d\"; "
            f"cat > '{p}.tmp'; sync '{p}.tmp' 2>/dev/null || true; chown wazuh:wazuh '{p}.tmp'; chmod 660 '{p}.tmp'; "
            f"mv -f '{p}.tmp' '{p}'; "
            f"if [ -f '{p}.cdb' ] && [ ! '{p}' -nt '{p}.cdb' ]; then "
            f"touch -d \"@$(( $(stat -c %Y '{p}.cdb') + 1 ))\" '{p}'; fi",
            stdin=data)

    def remove(self, rel: str) -> None:
        p = self._abs(rel)
        self._sh(f"rm -f '{p}'")

    def sha256(self, rels: list) -> dict:
        args = " ".join(f"'{self._abs(r)}'" for r in rels)
        out = self._sh(f"for f in {args}; do if [ -f \"$f\" ]; then sha256sum \"$f\"; else echo \"- $f\"; fi; done").decode()
        result = {}
        for line in out.splitlines():
            digest, path = line.split(None, 1)
            result[path[len(self.install_dir) + 1:]] = None if digest == "-" else digest
        return result

    def reload(self) -> dict:
        out = self._sh(f"{self.install_dir}/framework/python/bin/python3 -", stdin=_RELOAD_PY.encode())
        return json.loads(out.decode().strip().splitlines()[-1])

    def ruleset_ids(self, exclude: set) -> dict:
        """{relative path: [rule ids]} for every rule file analysisd loads on this node,
        from its own ossec.conf (<rule_dir>, <rule_include>, <rule_exclude>)."""
        conf = self.read("etc/ossec.conf").decode(errors="replace")
        dirs = re.findall(r"<rule_dir[^>]*>\s*([^<]+?)\s*</rule_dir>", conf)
        includes = re.findall(r"<rule_include>\s*([^<]+?)\s*</rule_include>", conf)
        excludes = set(re.findall(r"<rule_exclude>\s*([^<]+?)\s*</rule_exclude>", conf))
        listing = " ".join(f"'{self._abs(d)}'/*.xml" for d in dirs) + " " + " ".join(f"'{self._abs(i)}'" for i in includes)
        raw = self._sh(f"cd {self.install_dir}; tar -cf - $(ls -d {listing} 2>/dev/null | sed 's#^{self.install_dir}/##')")
        ids = {}
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            for member in tar.getmembers():
                name = member.name
                if name in exclude or name.rsplit("/", 1)[-1] in excludes or not member.isfile():
                    continue
                ids[name] = rule_order.rule_ids(tar.extractfile(member).read().decode(errors="replace"))
        return ids


@dataclass
class NodeResult:
    node: str
    role: str                # master | worker
    result: str              # ok | unchanged | warnings | errors | sync_timeout | rolled_back | rejected
    detail: list = field(default_factory=list)
    versions: dict = field(default_factory=dict)   # path -> sha256


@dataclass
class ApplyResult:
    ok: bool
    nodes: list
    problems: list = field(default_factory=list)


def _clean(resp: dict) -> bool:
    return bool(resp.get("success")) and not resp.get("warnings") and not resp.get("errors")


def _write(node, files: dict) -> None:
    # Lists first, rule file last: a rule must never be live before its lists exist.
    for path in sorted(files, key=lambda p: p.endswith(".xml")):
        if files[path] is None:
            node.remove(path)
        else:
            node.write_atomic(path, files[path])


def _tracked(bundle: dict) -> list:
    """Every file whose checksum must match before a worker reloads: the bundle plus
    each list's compiled .cdb (built by the master's reload, then synced)."""
    paths = list(bundle)
    paths += [p + ".cdb" for p in bundle if not p.endswith(".xml")]
    return sorted(paths)


def _wait_synced(node, expected: dict, timeout_s: float, poll_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if node.sha256(list(expected)) == expected:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_s)


def apply(master, workers: list, bundle: dict, sync_timeout_s: float = 120, poll_s: float = 2) -> ApplyResult:
    ti_rules = {p: b.decode() for p, b in bundle.items() if p.endswith(".xml")}
    problems = rule_order.check(master.ruleset_ids(exclude=set(bundle)), ti_rules)
    if problems:
        return ApplyResult(False, [NodeResult(master.name, "master", "rejected", problems)], problems)

    old = {p: master.read(p) for p in bundle}
    changed = any(old[p] != bundle[p] for p in bundle)
    if changed:
        _write(master, bundle)
        resp = master.reload()
        if not _clean(resp):
            _write(master, old)
            back = master.reload()
            detail = resp.get("warnings", []) + resp.get("errors", [])
            detail.append(f"rolled back to the previous files; rollback reload clean={_clean(back)}")
            return ApplyResult(False, [NodeResult(master.name, "master", "warnings" if resp.get("success") else "errors",
                                                  detail, master.sha256(_tracked(bundle)))], detail)
    expected = master.sha256(_tracked(bundle))
    results = [NodeResult(master.name, "master", "ok" if changed else "unchanged", [], expected)]

    failed_reload = False
    for w in workers:
        t0 = time.monotonic()
        synced = _wait_synced(w, expected, sync_timeout_s, poll_s)
        waited = f"checksums matched the master after {time.monotonic() - t0:.1f}s, then reloaded"
        if not synced:
            results.append(NodeResult(w.name, "worker", "sync_timeout",
                                      [f"checksums did not match the master within {sync_timeout_s:.0f}s; not reloaded"],
                                      w.sha256(list(expected))))
            continue
        if not changed:
            results.append(NodeResult(w.name, "worker", "unchanged", [], expected))
            continue
        resp = w.reload()
        if _clean(resp):
            results.append(NodeResult(w.name, "worker", "ok", [waited], expected))
        else:
            failed_reload = True
            results.append(NodeResult(w.name, "worker", "warnings" if resp.get("success") else "errors",
                                      resp.get("warnings", []) + resp.get("errors", []), expected))

    if failed_reload:
        # Same files, different outcome: config drift on that worker. Never leave the
        # cluster split between versions - put the previous files back everywhere.
        _write(master, old)
        master.reload()
        back = master.sha256(_tracked(bundle))
        for w in workers:
            if _wait_synced(w, back, sync_timeout_s, poll_s):
                w.reload()
        for r in results:
            if r.result == "ok":
                r.result, r.detail = "rolled_back", ["another node failed to reload; previous files restored"]
        return ApplyResult(False, results, [d for r in results for d in r.detail])

    return ApplyResult(all(r.result in ("ok", "unchanged") for r in results), results)


def entries(data: bytes) -> int:
    return sum(1 for line in data.splitlines() if line.strip()) if data else 0


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
