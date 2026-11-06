"""attack_runs recorder (Phase 7.0). The owner runs Atomic Red Team and Caldera; this only
RECORDS each run's window - it never executes anything. Normal activity and replays use it too.

  st-record start --technique T1136.001 --agent agent-ubuntu-1 --tool atomic [--test "..."] [--notes "..."]
  st-record stop <run_id> [--aborted]
  st-record caldera --operation <id> --url http://caldera:8888 [--api-key-env CALDERA_API_KEY]
  st-record list [--limit 20]

Every run lands in the TEST tenant. tool atomic -> source atomic_linux, caldera -> caldera,
normal -> normal_activity (label benign), replay -> replay:<dataset>.
"""
import argparse
import datetime as dt
import json
import os
import re
import secrets
import sys

from sqlalchemy import text

from . import db

SOURCES = {"atomic": "atomic_linux", "caldera": "caldera", "normal": "normal_activity"}
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def new_run_id(tool: str, now: dt.datetime = None) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    return f"{tool}-{now:%Y%m%dT%H%M%S}-{secrets.token_hex(3)}"


def start(conn, tenant: str, tool: str, agent: str, technique: str = None, test_name: str = None, label: str = None,
          source: str = None, dataset_id: str = None, recorded_by: str = None, details: dict = None,
          now: dt.datetime = None) -> str:
    if tool not in ("atomic", "caldera", "normal", "replay"):
        raise ValueError(f"unknown tool {tool!r}")
    if technique and tool in ("atomic", "caldera") and not TECHNIQUE.match(technique):
        raise ValueError(f"not an ATT&CK technique id: {technique!r}")
    now = now or dt.datetime.now(dt.timezone.utc)
    run_id = new_run_id(tool, now)
    conn.execute(text(
        "INSERT INTO attack_runs (run_id, tenant_key, tool, source, label, technique, test_name, agent, dataset_id, started_at, "
        " recorded_by, details) VALUES (:r, :t, :tool, :src, :lab, :tech, :test, :agent, :ds, :now, :by, CAST(:d AS jsonb))"),
        {"r": run_id, "t": tenant, "tool": tool, "src": source or SOURCES.get(tool, tool),
         "lab": label or ("benign" if tool == "normal" else "attack"), "tech": technique, "test": test_name,
         "agent": agent, "ds": dataset_id, "now": now, "by": recorded_by or os.environ.get("USER", "unknown"),
         "d": json.dumps(details or {})})
    return run_id


def stop(conn, run_id: str, aborted: bool = False, now: dt.datetime = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    r = conn.execute(text("UPDATE attack_runs SET ended_at = :now, status = :s WHERE run_id = :r AND status = 'running' "
                          "RETURNING run_id, technique, agent, started_at, ended_at"),
                     {"now": now, "s": "aborted" if aborted else "done", "r": run_id}).mappings().first()
    if r is None:
        raise SystemExit(f"no running run {run_id}")
    return dict(r)


def _ts(v):
    if not v:
        return None
    return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def import_caldera(conn, tenant: str, operation: dict, links: list, host_to_agent=None, now=None) -> str:
    """One attack_runs row per Caldera operation (tool caldera) and one attack_run_steps row
    per link (executed ability): technique, ability name, agent (by host), start/end, status.
    Commands are not stored."""
    host_to_agent = host_to_agent or (lambda h: h)
    times = [t for l in links for t in (_ts(l.get("decide")), _ts(l.get("finish"))) if t]
    agents = sorted({host_to_agent(l.get("host") or "") for l in links if l.get("host")})
    run_id = start(conn, tenant, "caldera", agents[0] if len(agents) == 1 else ",".join(agents),
                   technique=None, test_name=(operation.get("adversary") or {}).get("name") or operation.get("name"),
                   details={"operation_id": operation.get("id"), "operation_name": operation.get("name"),
                            "steps": len(links)},
                   now=min(times) if times else now)
    for n, l in enumerate(sorted(links, key=lambda x: str(x.get("decide") or "")), 1):
        ab = l.get("ability") or {}
        conn.execute(text(
            "INSERT INTO attack_run_steps (run_id, step_no, technique, name, agent, started_at, ended_at, status, details) "
            "VALUES (:r, :n, :t, :name, :a, :s, :e, :st, CAST(:d AS jsonb))"),
            {"r": run_id, "n": n, "t": ab.get("technique_id"), "name": ab.get("name"), "a": host_to_agent(l.get("host") or ""),
             "s": _ts(l.get("decide")), "e": _ts(l.get("finish")), "st": str(l.get("status")),
             "d": json.dumps({"tactic": ab.get("tactic"), "technique_name": ab.get("technique_name"),
                              "ability_id": ab.get("ability_id"), "link_id": l.get("id")})})
    conn.execute(text("UPDATE attack_runs SET ended_at = :e, status = 'done' WHERE run_id = :r"),
                 {"e": max(times) if times else now, "r": run_id})
    return run_id


def fetch_caldera(url: str, api_key: str, operation_id: str) -> tuple:
    import requests
    h = {"KEY": api_key}
    op = requests.get(f"{url.rstrip('/')}/api/v2/operations/{operation_id}", headers=h, timeout=30)
    op.raise_for_status()
    links = requests.get(f"{url.rstrip('/')}/api/v2/operations/{operation_id}/links", headers=h, timeout=30)
    links.raise_for_status()
    return op.json(), links.json()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="st-record", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--technique", required=True)
    s.add_argument("--agent", required=True)
    s.add_argument("--tool", choices=["atomic", "caldera", "normal"], required=True)
    s.add_argument("--test", default=None)
    s.add_argument("--notes", default=None)
    e = sub.add_parser("stop")
    e.add_argument("run_id")
    e.add_argument("--aborted", action="store_true")
    c = sub.add_parser("caldera")
    c.add_argument("--operation", required=True)
    c.add_argument("--url", default="http://127.0.0.1:8888")
    c.add_argument("--api-key-env", default="CALDERA_API_KEY")
    l = sub.add_parser("list")
    l.add_argument("--limit", type=int, default=20)
    a = p.parse_args(argv)
    tenant = db.test_tenant()
    with db.engine().begin() as conn:
        if a.cmd == "start":
            print(start(conn, tenant, a.tool, a.agent, a.technique, a.test, details={"notes": a.notes} if a.notes else None))
        elif a.cmd == "stop":
            r = stop(conn, a.run_id, a.aborted)
            print(f"{r['run_id']} {r['technique']} {r['agent']} {r['started_at']:%H:%M:%S} -> {r['ended_at']:%H:%M:%S}")
        elif a.cmd == "caldera":
            key = os.environ.get(a.api_key_env, "")
            if not key:
                raise SystemExit(f"{a.api_key_env} is not set")
            op, links = fetch_caldera(a.url, key, a.operation)
            run_id = import_caldera(conn, tenant, op, links)
            print(run_id, f"{len(links)} steps")
        else:
            for r in conn.execute(text("SELECT run_id, tool, label, technique, agent, started_at, ended_at, status FROM attack_runs "
                                       "WHERE tenant_key = :t ORDER BY started_at DESC LIMIT :n"), {"t": tenant, "n": a.limit}):
                print(" | ".join(str(x) for x in r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
