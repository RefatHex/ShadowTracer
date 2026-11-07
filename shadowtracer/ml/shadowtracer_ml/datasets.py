"""Public recorded datasets (Phase 7.0, docs/ML_FOUNDATION.md "Recorded datasets").

Never committed: this module downloads to ST_DATA (default /home/refat/st-data/datasets),
outside the repo. Licences were read on 2026-11-06; the owner decided which are used.

  python -m shadowtracer_ml.datasets inventory
  python -m shadowtracer_ml.datasets download splunk [--techniques T1136.001,T1059.001,...]
  python -m shadowtracer_ml.datasets download evtx
  python -m shadowtracer_ml.datasets download otrf
"""
import json
import os
import subprocess
import sys
import urllib.request

ST_DATA = os.environ.get("ST_DATA", "/home/refat/st-data/datasets")
MAX_FILE_BYTES = 60 * 1024 * 1024

# dataset, OS, log types, ATT&CK labels, size, licence, usable (owner decision 2026-11-06)
INVENTORY = [
    {"dataset": "Splunk attack_data", "url": "https://github.com/splunk/attack_data", "os": "Windows, Linux",
     "logs": "Windows Security/Sysmon/PowerShell/System as XmlWinEventLog (1 event per line), Linux auditd, Sysmon for Linux",
     "attack_labels": "per technique folder + YAML mitre_technique", "size": ">9 GB (Git LFS)", "licence": "Apache-2.0",
     "usable": "yes (Windows XML replayed; Linux auditd decodes but reaches only level-0 Wazuh rules without Wazuh audit keys)"},
    {"dataset": "OTRF Security-Datasets", "url": "https://github.com/OTRF/Security-Datasets", "os": "Windows (mostly), some Linux/cloud",
     "logs": "Windows Security, Sysmon, PowerShell as JSON (zipped, one event per line)",
     "attack_labels": "per dataset metadata YAML (ATT&CK technique ids)", "size": "several GB", "licence": "MIT",
     "usable": "yes (JSON rebuilt into event XML)"},
    {"dataset": "EVTX-ATTACK-SAMPLES", "url": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", "os": "Windows",
     "logs": "EVTX (Security, Sysmon, System, ...)", "attack_labels": "folder per tactic; technique in some file names",
     "size": "~200 samples, tens of MB", "licence": "GPL-3.0",
     "usable": "yes - internal training only, never redistributed (owner decision)"},
    {"dataset": "AIT Log Data Set V2.0", "url": "https://zenodo.org/records/5789064", "os": "Linux",
     "logs": "auth, syslog, apache, audit, suricata, dns, vpn, ...", "attack_labels": "attack-step labels per line (not ATT&CK ids)",
     "size": "130.6 GB", "licence": "CC BY-NC-SA 4.0", "usable": "no (non-commercial)"},
    {"dataset": "Splunk BOTSv3", "url": "https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz", "os": "Windows, Linux",
     "logs": "Windows Sysmon/WinEventLog, Linux linux_secure/linux_audit, AWS/stream (real benign background + attack)",
     "attack_labels": "scenario attack windows/hosts at tactic level (no per-event labels); off-window on affected hosts = benign background",
     "size": "320 MB (pre-indexed Splunk app)", "licence": "CC0", "usable": "pending: raw events must be exported from the "
     "pre-indexed buckets (throwaway Splunk, owner decision 2026-11-07); Windows benign fills the OS-shortcut gap (docs/ML_FOUNDATION.md B)"},
    {"dataset": "DARPA OpTC", "url": "https://github.com/FiveDirections/OpTC-data", "os": "Windows, Linux",
     "logs": "eCAR host telemetry, labelled", "attack_labels": "red-team activity labelled", "size": "~1 TB",
     "licence": "unclear", "usable": "no (future work: licence unclear, size impractical; not downloaded)"},
]
# Windows techniques whose Splunk atomic_red_team folders hold XmlWinEventLog recordings.
SPLUNK_TECHNIQUES = ["T1136.001", "T1059.001", "T1003.001", "T1053.005", "T1547.001", "T1218.011", "T1112", "T1070.001",
                     "T1087.002", "T1482", "T1069.001", "T1543.003", "T1105", "T1027", "T1569.002", "T1078", "T1098",
                     "T1548.002", "T1562.001", "T1021.002"]
SPLUNK_XML_FILES = ("windows-sysmon.log", "windows-xml.log", "xml-windows-security.log", "windows-security-xml.log")


def _get(url: str, path: str, max_bytes: int = MAX_FILE_BYTES) -> bool:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return True
    req = urllib.request.Request(url, headers={"User-Agent": "shadowtracer-ml-datasets"})
    with urllib.request.urlopen(req, timeout=300) as r:
        size = int(r.headers.get("Content-Length") or 0)
        if size > max_bytes:
            return False
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        return False
    with open(path + ".tmp", "wb") as f:
        f.write(data)
    os.rename(path + ".tmp", path)
    return True


def download_splunk(techniques=SPLUNK_TECHNIQUES) -> list:
    tree_path = os.path.join(ST_DATA, "splunk", "tree.json")
    _get("https://api.github.com/repos/splunk/attack_data/git/trees/master?recursive=1", tree_path, 64 * 1024 * 1024)
    tree = json.load(open(tree_path))["tree"]
    out = []
    for e in tree:
        p = e["path"]
        parts = p.split("/")
        if (len(parts) == 5 and parts[0] == "datasets" and parts[1] == "attack_techniques" and parts[2] in techniques
                and parts[3] == "atomic_red_team" and parts[4] in SPLUNK_XML_FILES):
            dest = os.path.join(ST_DATA, "splunk", "win", f"{parts[2]}_{parts[4]}")
            ok = _get(f"https://media.githubusercontent.com/media/splunk/attack_data/master/{p}", dest)
            out.append({"technique": parts[2], "file": dest, "downloaded": ok})
    return out


def download_botsv3() -> dict:
    """BOTSv3 (CC0): a 320 MB pre-indexed Splunk app. The Windows Sysmon events are XmlWinEventLog
    stored as <Event> XML inside the buckets' rawdata/journal.gz, so no Splunk is needed to export
    them - replay.iter_botsv3_sysmon reads them directly. Downloads + extracts once."""
    import tarfile
    base = os.path.join(ST_DATA, "botsv3")
    tgz = os.path.join(base, "botsv3_data_set.tgz")
    _get("https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz", tgz, 512 * 1024 * 1024)
    extract = os.path.join(base, "extracted")
    if not os.path.isdir(extract):
        with tarfile.open(tgz) as t:
            t.extractall(extract)   # noqa: S202 - trusted CC0 dataset; extracted into its own dir
    return {"tgz": tgz, "extracted": extract, "md5_expected": "d7ccca99a01cff070dff3c139cdc10eb"}


def download_evtx() -> str:
    dest = os.path.join(ST_DATA, "evtx-attack-samples")
    if not os.path.isdir(dest):
        subprocess.run(["git", "clone", "--depth", "1", "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git", dest], check=True)
    return dest


def download_otrf(limit: int = 30) -> list:
    """The atomic Windows host datasets with an ATT&CK mapping in their metadata, up to `limit`."""
    base = os.path.join(ST_DATA, "otrf")
    tree_path = os.path.join(base, "tree.json")
    _get("https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1", tree_path, 64 * 1024 * 1024)
    tree = [e["path"] for e in json.load(open(tree_path))["tree"]]
    metas = [p for p in tree if p.startswith("datasets/atomic/_metadata/") and p.endswith(".yaml")]
    out = []
    for m in metas:
        if len(out) >= limit:
            break
        mpath = os.path.join(base, "meta", os.path.basename(m))
        if not _get(f"https://raw.githubusercontent.com/OTRF/Security-Datasets/master/{m}", mpath, 1024 * 1024):
            continue
        meta = open(mpath).read()
        if "platform:" in meta and "Windows" not in meta:
            continue
        for line in meta.splitlines():
            line = line.strip()
            if line.startswith("link:") and line.endswith(".zip") and "/host/" in line:
                url = line.split("link:", 1)[1].strip()
                dest = os.path.join(base, "host", os.path.basename(url))
                ok = _get(url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/"), dest)
                out.append({"metadata": os.path.basename(m), "file": dest, "downloaded": ok})
                break
    return out


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] == "inventory":
        cols = ["dataset", "os", "logs", "attack_labels", "size", "licence", "usable"]
        print("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols))
        for d in INVENTORY:
            print("| " + " | ".join(str(d[c]) for c in cols) + " |")
        return 0
    what = argv[1]
    if what == "splunk":
        tech = argv[3].split(",") if len(argv) > 3 and argv[2] == "--techniques" else SPLUNK_TECHNIQUES
        r = download_splunk(tech)
    elif what == "evtx":
        r = download_evtx()
    elif what == "botsv3":
        r = download_botsv3()
    else:
        r = download_otrf()
    print(json.dumps(r, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
