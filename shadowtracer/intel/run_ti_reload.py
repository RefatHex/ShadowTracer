"""Distribute the ShadowTracer TI bundle to one tenant's manager cluster (lab CLI).

usage (from shadowtracer/intel):
  .venv/bin/python run_ti_reload.py --tenant-key <key> \\
      --node master=shadowtracer-lab-shadowtracer-master-1 \\
      --node worker1=shadowtracer-lab-shadowtracer-worker1-1 ...
The first --node is the cluster master. Results go to Postgres ti_list_versions
(POSTGRES_* env, as for alembic) for /health/detail. Exit code 0 only if every node
ended ok/unchanged.
--rules-file <path> replaces the generated TI rule file (used to prove a bad file is
rejected or rolled back). Test-only.
"""
import argparse
import os
import sys

from sqlalchemy import create_engine, text

from shadowtracer_intel import safe_reload, ti_rules

UPSERT = text(
    "INSERT INTO ti_list_versions (tenant_key, node, path, role, sha256, entries, result, detail, checked_at) "
    "VALUES (:tenant_key, :node, :path, :role, :sha256, :entries, :result, :detail, now()) "
    "ON CONFLICT (tenant_key, node, path) DO UPDATE SET role=EXCLUDED.role, sha256=EXCLUDED.sha256, "
    "entries=EXCLUDED.entries, result=EXCLUDED.result, detail=EXCLUDED.detail, checked_at=now()")


def record(engine, tenant_key: str, result: safe_reload.ApplyResult, bundle: dict) -> None:
    with engine.begin() as conn:
        for r in result.nodes:
            conn.execute(text("DELETE FROM ti_list_versions WHERE tenant_key=:t AND node=:n"),
                         {"t": tenant_key, "n": r.node})
            rows = r.versions.items() or [("*", None)]
            for path, digest in rows:
                conn.execute(UPSERT, {
                    "tenant_key": tenant_key, "node": r.node, "path": path, "role": r.role,
                    # an entry count only where the node really holds this bundle's content
                    "sha256": digest, "entries": safe_reload.entries(bundle[path])
                    if path in bundle and digest == safe_reload.sha(bundle[path]) else None,
                    "result": r.result, "detail": "\n".join(r.detail)[:4000],
                })


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tenant-key", required=True)
    p.add_argument("--node", action="append", required=True, help="name=container; first is the master")
    p.add_argument("--rules-file", help="test only: publish this rule file instead of the generated one")
    p.add_argument("--sync-timeout", type=float, default=120)
    p.add_argument("--no-record", action="store_true")
    args = p.parse_args()

    nodes = [safe_reload.DockerNode(*n.split("=", 1)) for n in args.node]
    bundle = ti_rules.bundle()
    if args.rules_file:
        bundle[ti_rules.RULES_FILE] = open(args.rules_file, "rb").read()

    result = safe_reload.apply(nodes[0], nodes[1:], bundle, sync_timeout_s=args.sync_timeout)
    for r in result.nodes:
        print(f"{r.node:12} {r.role:6} {r.result:12} " + "; ".join(r.detail))
    if not args.no_record:
        url = (f"postgresql+psycopg2://{os.environ.get('POSTGRES_USER', 'shadowtracer')}:"
               f"{os.environ.get('POSTGRES_PASSWORD', '')}@{os.environ.get('POSTGRES_HOST', '127.0.0.1')}:"
               f"{os.environ.get('POSTGRES_PORT', '5432')}/{os.environ.get('POSTGRES_DB', 'shadowtracer')}")
        record(create_engine(url), args.tenant_key, result, bundle)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
