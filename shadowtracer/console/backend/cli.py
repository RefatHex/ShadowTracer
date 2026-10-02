#!/usr/bin/env python3
"""Admin CLI. No default admin account ships anywhere - this is the only
way the first one gets created, and it always prompts for the password
interactively rather than accepting one on the command line (shell
history, process list)."""

import argparse
import getpass
import sys

from sqlalchemy import select

from app import security
from app.audit import append_entry, verify_chain
from app.config import load_settings
from app.db import make_session_factory
from app.models import tenants, users


def create_admin(args) -> int:
    settings = load_settings()
    Session = make_session_factory(settings)
    db = Session()

    tenant_row = db.execute(select(tenants).where(tenants.c.name == args.tenant)).mappings().first()
    if tenant_row is None:
        result = db.execute(tenants.insert().values(name=args.tenant).returning(tenants.c.id))
        tenant_id = result.scalar_one()
        db.commit()
        print(f"created tenant {args.tenant!r} (id={tenant_id})")
    else:
        tenant_id = tenant_row["id"]

    existing = db.execute(
        select(users).where(users.c.tenant_id == tenant_id, users.c.email == args.email)
    ).mappings().first()
    if existing is not None:
        print(f"user {args.email!r} already exists in tenant {args.tenant!r}", file=sys.stderr)
        return 1

    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("passwords did not match", file=sys.stderr)
        return 1
    if len(password) < 12:
        print("password must be at least 12 characters", file=sys.stderr)
        return 1

    db.execute(
        users.insert().values(
            tenant_id=tenant_id, email=args.email,
            password_hash=security.hash_password(password), role="admin",
        )
    )
    db.commit()
    append_entry(db, actor="cli:create-admin", tenant_id=tenant_id, action="create_admin", target=args.email, outcome="success")
    print(f"created admin {args.email!r} in tenant {args.tenant!r}")
    return 0


def verify_audit_chain(args) -> int:
    settings = load_settings()
    Session = make_session_factory(settings)
    db = Session()

    result = verify_chain(db)
    if result.total_rows == 0:
        print("audit_log is empty - nothing to verify")
        return 0
    if result.valid:
        print(f"OK: {result.total_rows} rows, chain verified from genesis to the latest row")
        return 0

    print(f"BROKEN CHAIN: first bad row is id={result.first_broken_row_id}", file=sys.stderr)
    print(f"reason: {result.reason}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="ShadowTracer console admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    create_admin_parser = sub.add_parser("create-admin", help="create the first admin user for a tenant")
    create_admin_parser.add_argument("--tenant", required=True, help="tenant name (created if it doesn't exist)")
    create_admin_parser.add_argument("--email", required=True)
    create_admin_parser.set_defaults(func=create_admin)

    verify_chain_parser = sub.add_parser("verify-audit-chain", help="verify the audit log's hash chain")
    verify_chain_parser.set_defaults(func=verify_audit_chain)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
