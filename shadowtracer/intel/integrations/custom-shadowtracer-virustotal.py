# ShadowTracer VirusTotal integration, manager side (Phase 6.3, THREAT_INTEL.md §1.8).
#
# integratord runs this once per matching FIM alert (rules 550/554), serially and off
# analysisd's path. It makes NO network call and holds no key: it only spools the new
# file hash to a local directory. ti-sync's VirusTotal worker collects the spool, checks
# the tenant's opt-in, the verdict cache and the API budget, looks the SHA-256 up
# (hashes only, never files) and sends a malicious verdict back to this manager as an
# event in the shape of Wazuh's own virustotal integration (rules 0490 + ShadowTracer's
# TI rule). Runs with the manager's framework Python, standard library only.
import json
import os
import re
import sys

SPOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "var", "shadowtracer-vt")
MAX_SPOOLED = 10000          # the worker is down or the tenant is off: never fill the disk
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def main(argv) -> int:
    with open(argv[1]) as f:
        alert = json.load(f)
    sc = alert.get("syscheck") or {}
    sha256 = str(sc.get("sha256_after", "")).lower()
    if not SHA256.match(sha256):
        return 0                                            # no content hash (e.g. a deletion)
    os.makedirs(SPOOL, exist_ok=True)
    if len(os.listdir(SPOOL)) >= MAX_SPOOLED:
        return 0
    agent = alert.get("agent") or {}
    req = {"sha256": sha256, "md5": sc.get("md5_after"), "sha1": sc.get("sha1_after"), "path": sc.get("path"),
           "alert_id": alert.get("id"), "alert_time": alert.get("timestamp"), "rule_id": (alert.get("rule") or {}).get("id"),
           "node": (alert.get("cluster") or {}).get("node") or (alert.get("manager") or {}).get("name"),
           "agent": {"id": agent.get("id"), "name": agent.get("name"), "ip": agent.get("ip", "any")}}
    name = f"{sha256}.{re.sub(r'[^0-9A-Za-z.]', '_', str(alert.get('id', 'x')))}.json"
    tmp = os.path.join(SPOOL, "." + name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(req, f)
    os.rename(tmp, os.path.join(SPOOL, name))              # the worker never sees a half-written file
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # noqa: BLE001 - never let one alert break integratord
        print(f"custom-shadowtracer-virustotal: {exc}", file=sys.stderr)
        sys.exit(1)
