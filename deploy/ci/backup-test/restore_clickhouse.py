#!/usr/bin/env python3
"""Phase 5.6 Item 6: automates the one manual step Phase 5.5 Item 4's real
restore test needed by hand (docs/design/BACKUP_RESTORE.md Sec 2) - cleaning
up stale Keeper replica registrations left behind by DROP DATABASE before
RESTORE DATABASE can recreate the Replicated tables. Without this,
RESTORE fails with REPLICA_ALREADY_EXISTS.

Generic rather than a hardcoded table list: lists whatever is actually
registered under /clickhouse/tables/{shard} in Keeper right now and drops
each one's replica registration before restoring - correct for any table
this schema has today or adds later, not just the two tables Phase 5.5
happened to hit.
"""
import argparse
import os

import clickhouse_connect


def clean_stale_keeper_replicas(client, shard: str, replica: str) -> list[str]:
    base = f"/clickhouse/tables/{shard}"
    try:
        children = client.query(f"SELECT name FROM system.zookeeper WHERE path = '{base}'").result_rows
    except Exception as exc:
        print(f"could not list {base} in Keeper (ok if nothing is registered there yet): {exc}")
        return []

    cleaned = []
    for (table,) in children:
        zkpath = f"{base}/{table}"
        try:
            client.command(f"SYSTEM DROP REPLICA '{replica}' FROM ZKPATH '{zkpath}'")
            cleaned.append(table)
        except Exception as exc:
            # Not every registered table necessarily blocks a restore (Phase
            # 5.5 only hit it for 2 of 5) - a drop that fails because the
            # local table already references this registration (nothing
            # stale here) is expected, not an error.
            print(f"skipped {zkpath}: {exc}")
    return cleaned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="shadowtracer")
    parser.add_argument("--shard", default="01")
    parser.add_argument("--replica", default="01")
    parser.add_argument("--backup-name", required=True, help="name passed to Disk('backups', <name>)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("CLICKHOUSE_PORT", "8123")))
    args = parser.parse_args()

    client = clickhouse_connect.get_client(
        host=args.host, port=args.port,
        username=os.environ["CLICKHOUSE_USER"], password=os.environ["CLICKHOUSE_PASSWORD"],
    )

    cleaned = clean_stale_keeper_replicas(client, args.shard, args.replica)
    print(f"cleaned stale Keeper replica registrations for: {cleaned or '(none found)'}")

    client.command(f"RESTORE DATABASE {args.database} FROM Disk('backups', '{args.backup_name}')")
    print(f"RESTORE DATABASE {args.database} succeeded")


if __name__ == "__main__":
    main()
