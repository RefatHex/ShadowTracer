"""phase 6.1b: threat-intel IOC store (STIX 2.1-compatible), sources, allowlists

Revision ID: 14998d8588fb
Revises: 0e5c1aad5005
Create Date: 2026-11-06

shadowtracer/docs/design/THREAT_INTEL.md §4.1. One iocs row per observable per
tenant scope (tenant_key NULL = global); every source's claim about it is an
ioc_sightings row (pulse/event id, link, the source's own confidence, TLP,
tags, MITRE ids, first/last seen, the source's own expiry). Combined
confidence and expiry are computed from the live sightings at list
generation (decay is time-dependent) and written back for display.
ti_sources carries per-source staleness for /health/detail. ti_allowlist
holds MISP warninglists, global and per-tenant allowlists and protected
assets; an allowlisted value never enters a list.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = '14998d8588fb'
down_revision: Union[str, Sequence[str], None] = '0e5c1aad5005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"
TYPES = "('ipv4','ipv6','cidr4','cidr6','domain','url','md5','sha1','sha256')"
TLPS = "('clear','green','amber','amber+strict','red')"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text(f"""
    CREATE TABLE ti_sources (
      id              bigserial PRIMARY KEY,
      name            text NOT NULL UNIQUE,
      kind            text NOT NULL,                 -- feodo | sslbl | otx | manual | ...
      tenant_key      text NULL,                     -- NULL = global source
      stix_identity   text NOT NULL,                 -- created_by_ref
      trust           real NOT NULL CHECK (trust BETWEEN 0 AND 1),
      default_tlp     text NOT NULL CHECK (default_tlp IN {TLPS}),
      enabled         boolean NOT NULL DEFAULT true,
      sync_cursor     text,
      last_attempt_at timestamptz,
      last_success_at timestamptz,
      last_error      text,
      last_counts     jsonb NOT NULL DEFAULT '{{}}'
    );
    CREATE TABLE iocs (                              -- STIX 2.1 indicator
      id                bigserial PRIMARY KEY,
      stix_id           text NOT NULL UNIQUE,        -- indicator--<uuid5(scope,type,value)>
      tenant_key        text NULL,
      type              text NOT NULL CHECK (type IN {TYPES}),
      value             text NOT NULL,               -- normalised (normalise.py)
      pattern           text NOT NULL,               -- STIX pattern
      pattern_type      text NOT NULL DEFAULT 'stix',
      indicator_types   text[] NOT NULL DEFAULT '{{malicious-activity}}',
      tlp               text NOT NULL CHECK (tlp IN {TLPS}),
      confidence        smallint NOT NULL DEFAULT 0,
      labels            text[] NOT NULL DEFAULT '{{}}',
      mitre             text[] NOT NULL DEFAULT '{{}}',
      valid_from        timestamptz NOT NULL,
      last_seen         timestamptz NOT NULL,
      valid_until       timestamptz NOT NULL,
      revoked           boolean NOT NULL DEFAULT false,
      created           timestamptz NOT NULL DEFAULT now(),
      modified          timestamptz NOT NULL DEFAULT now(),
      UNIQUE NULLS NOT DISTINCT (tenant_key, type, value)
    );
    CREATE INDEX iocs_scope ON iocs (tenant_key, type) WHERE NOT revoked;
    CREATE INDEX iocs_created ON iocs (created);
    CREATE TABLE ioc_sightings (
      ioc_id            bigint NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
      source_id         bigint NOT NULL REFERENCES ti_sources(id),
      source_ref        text,                         -- OTX pulse id / feed entry id
      reference_url     text,
      source_confidence real,                         -- 0-1, NULL if the source has none
      tlp               text NOT NULL CHECK (tlp IN {TLPS}),
      labels            text[] NOT NULL DEFAULT '{{}}',
      mitre             text[] NOT NULL DEFAULT '{{}}',
      first_seen        timestamptz NOT NULL,
      last_seen         timestamptz NOT NULL,
      valid_until       timestamptz NULL,             -- the source's own expiry, if any
      revoked_at        timestamptz NULL,
      PRIMARY KEY (ioc_id, source_id)
    );
    CREATE INDEX ioc_sightings_source ON ioc_sightings (source_id) WHERE revoked_at IS NULL;
    CREATE TABLE ti_allowlist (
      id          bigserial PRIMARY KEY,
      tenant_key  text NULL,                          -- NULL = global
      type        text NOT NULL CHECK (type IN {TYPES}),
      value       text NOT NULL,                      -- exact value, or CIDR for IP types
      kind        text NOT NULL CHECK (kind IN ('warninglist','manual','protected_asset','fp_marking')),
      reason      text NOT NULL,
      origin_ref  text,                               -- warninglist name / ti_hit id
      created_by  text NOT NULL,
      created_at  timestamptz NOT NULL DEFAULT now(),
      expires_at  timestamptz NULL,
      UNIQUE NULLS NOT DISTINCT (tenant_key, type, value, kind)
    );
    """))
    for t in ("ti_sources", "iocs", "ioc_sightings", "ti_allowlist"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {APP_ROLE}"))
    for s in ("ti_sources_id_seq", "iocs_id_seq", "ti_allowlist_id_seq"):
        conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE {s} TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE ti_allowlist, ioc_sightings, iocs, ti_sources"))
