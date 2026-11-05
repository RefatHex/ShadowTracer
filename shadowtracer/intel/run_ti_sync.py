"""ti-sync entry point.
  run_ti_sync.py                      run forever (TI_SYNC_INTERVAL_SECONDS)
  run_ti_sync.py once                 one cycle, print the report
  run_ti_sync.py add-ioc --tenant T --type ipv4 --value V [--confidence 0.9] [--tlp amber]
                                      tenant-private (or --tenant global) manual IOC
  run_ti_sync.py allow --tenant T|global --type ipv4 --value V --kind manual|protected_asset --reason R
"""
import argparse
import json
import sys

from sqlalchemy import create_engine

from shadowtracer_intel import store, sync
from shadowtracer_intel.feeds import Observation


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("once")
    a = sub.add_parser("add-ioc")
    a.add_argument("--tenant", required=True); a.add_argument("--type", required=True); a.add_argument("--value", required=True)
    a.add_argument("--confidence", type=float, default=0.9); a.add_argument("--tlp", default="amber"); a.add_argument("--ref", default="manual")
    w = sub.add_parser("allow")
    w.add_argument("--tenant", required=True); w.add_argument("--type", required=True); w.add_argument("--value", required=True)
    w.add_argument("--kind", choices=["manual", "protected_asset"], required=True); w.add_argument("--reason", required=True)
    args = p.parse_args()
    if args.cmd is None:
        sync.main()
        return 0
    engine = create_engine(sync.database_url())
    if args.cmd == "once":
        print(json.dumps(sync.run_once(engine), indent=1, default=str))
        return 0
    tenant = None if args.tenant == "global" else args.tenant
    with engine.begin() as conn:
        if args.cmd == "add-ioc":
            sid = store.ensure_source(conn, f"manual:{args.tenant}", "manual", tenant_key=tenant)
            counts = store.apply_observations(conn, sid, tenant, [Observation(
                args.type, args.value, source_ref=args.ref, source_confidence=args.confidence, tlp=args.tlp)], snapshot=False)
            print(json.dumps(counts))
            return 0 if counts["accepted"] == 1 else 1
        n = store.replace_allowlist(conn, args.kind, f"cli:{args.value}", [(args.type, args.value)], tenant, args.reason, "cli")
        print(f"allowlisted {n}")
        return 0 if n == 1 else 1


if __name__ == "__main__":
    sys.exit(main())
