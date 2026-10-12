# Threat model outline (Phase 5.5 Item 6)

Status: **report only, no fixes** - per instruction. Every "what protects it today"
claim below is evidence (a command, a file, a line number), not a guess. Ranked top 10
at the end.

## 0. Trust boundary diagram (today's real topology)

```
[agent] --(1514/1515, Wazuh's own encrypted protocol)--> [manager]
[manager] --(local file: alerts.json/archives.json, read-only mount)--> [shipper]
[shipper] --(Kafka PLAINTEXT, no auth)--> [Kafka: events.raw / events.dead-letter]
[Kafka] --(PLAINTEXT, no auth)--> [writer] --(HTTP, no TLS)--> [ClickHouse]
[Kafka] --(PLAINTEXT, no auth)--> [correlator/closer] --(plain TCP, ssl=off)--> [Postgres]
[browser] --(HTTPS, Caddy-terminated)--> [console-backend] --(HTTP/plain TCP)--> [ClickHouse/Postgres/Kafka]
[tenant A's data] <--RBAC/JWT scoping--> [tenant B's data]  (same Postgres/ClickHouse instances)
[rule/feed updates]  -- does not exist yet (see §8)
[future SOAR]        -- does not exist yet (see §9)
```

## 1. agent -> manager

**Protects it today**: Wazuh's own built-in secure protocol (shared-key encrypted
channel established at enrollment, port 1515; encrypted event channel, port 1514) -
inherited, unmodified by ShadowTracer. Not re-audited here (out of this item's scope -
it's upstream Wazuh's own security model, 20+ years hardened); flagged as "trust the
upstream project" rather than independently re-verified.

**STRIDE**: Spoofing (an agent impersonating another, mitigated by per-agent key
material from enrollment); Tampering (mitigated by the encrypted channel). Lowest
relative risk of every boundary in this model, because it's the one piece of this
architecture neither built nor modified by this project.

## 2. manager -> shipper

**Protects it today**: not a network boundary at all - the shipper tails
`alerts.json`/`archives.json` from a **read-only** Docker bind mount
(`deploy/lab/docker-compose.yml`: `./alerts-worker1:/var/ossec/logs/alerts:ro`).
Confirmed read-only in the compose file for every shipper.

**STRIDE**: Tampering is the only live concern - whatever a compromised manager
process can write into its own alert log, the shipper will faithfully ship as if it
were real. No Spoofing/Information Disclosure here (no network hop), no further
authentication expected or needed for a same-host file read.

## 3. shipper -> Kafka, and Kafka -> consumers (writer/correlator)

**Protects it today - confirmed directly, not assumed**:
`KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT`
(`deploy/lab/docker-compose.yml`) - **every listener, internal and external, is
plaintext with no SASL/authentication configured anywhere** (grepped the whole compose
file for `SASL`/`SSL`/`TLS`: zero matches). The external listener is bound to
`127.0.0.1` only in the lab, but nothing in the broker's own config enforces that -
it's a host firewall/port-publishing choice, not a Kafka-level control.

**STRIDE**: this is the widest-open boundary in the whole system.
- **Spoofing**: any process that can reach the broker can produce a message with any
  `tenant_id` header it likes - there is no check that the producer *is* the tenant it
  claims to be, because nothing authenticates the producer at all.
- **Tampering**: same reach - any reachable client can produce directly onto
  `events.raw`, bypassing the shipper (and whatever trust the shipper's own `TENANT_ID`
  env var was meant to establish) entirely.
- **Information Disclosure**: any reachable client can consume any topic, including
  other tenants' raw events, with zero authorization check.
- **Denial of Service**: no client quotas/authentication means no way to rate-limit or
  block a single misbehaving/malicious producer short of a network-level block.

This matters more than it would in isolation because of §3's finding above: **TENANT_ID
is the single thing standing between tenants today** (per `docs/design/TENANCY.md`),
and it is asserted by the shipper into an otherwise-unauthenticated message bus - a
network position that can reach Kafka can bypass that assertion completely.

## 4. services -> ClickHouse / Postgres

**Protects it today**: password authentication on both (`CLICKHOUSE_PASSWORD`,
`POSTGRES_PASSWORD`/`APP_DB_PASSWORD`), but **confirmed in transit as plaintext for
both** - `docker exec shadowtracer-lab-postgres-1 psql ... -c "SHOW ssl;"` ->
**`off`**; `clickhouse_connect.get_client()` in `writer.py:94-97` passes no
`interface="https"`, so it's plain HTTP - a password sent over HTTP Basic Auth, in
cleartext, on the Docker network.

**Real asymmetry found**: Postgres has genuine least-privilege separation - every
pipeline service (writer, correlator, closer; confirmed in `run_correlator.py:57`)
connects as the restricted `shadowtracer_app` role (`GRANT`/`REVOKE` per table,
e.g. `audit_log` is append-only - `REVOKE UPDATE, DELETE ON audit_log FROM
shadowtracer_app`, `shadowtracer/ingest/alembic/versions/5f408777ad31_*.py:77`), not
the Postgres admin. **ClickHouse has no equivalent** - grepped `events_schema.sql` for
`CREATE USER`/`GRANT`/`ROLE`: zero matches. Every service (shipper, writer, closer,
console-backend) connects to ClickHouse as the **same single admin-equivalent
credential**.

**STRIDE**: Information Disclosure (cleartext credentials and data on the wire, to
anyone who can observe Docker network traffic - a real concern once this runs across
real hosts, not just one Docker daemon's internal bridge); Elevation of Privilege (any
service compromised via any other vector inherits full ClickHouse access, since there
is no per-service ClickHouse role to contain it - the shipper, which should only ever
need to write dead-letter rows, can read/write/drop anything).

## 5. browser -> console

**Protects it today**: real TLS - Caddy terminates HTTPS on 8443
(`deploy/lab/console-caddy.Dockerfile`, `docker-compose.yml`'s `caddy` service).
**This is the one internal-facing boundary with transport encryption actually
configured.**

**STRIDE**: standard web-app surface - JWT in `Authorization` header (not a cookie, so
CSRF is a smaller concern by construction), `CORS_ALLOW_ORIGINS` explicitly set (not
`*`). Lower relative risk than the data-platform boundaries above, mainly because this
one already got real TLS.

## 6. tenant <-> tenant

**Protects it today**: every console query scoped by the JWT's `tenant_id`
(`app/rbac.py:37-57`, confirmed in Item 1's research) - a real, working control.

**Real single point of failure found**: **one shared `JWT_SECRET` signs every
tenant's tokens.** Compromise of that one secret (e.g. via the ClickHouse/Postgres
cleartext-credential exposure in §4, if `JWT_SECRET` ever sat in a database row, or
simply via host/container compromise) lets an attacker forge a valid token claiming
**any** `tenant_id` - cross-tenant impersonation in one step, not tenant-by-tenant.
This is the same class of finding as `docs/design/TENANCY.md`'s fingerprint-isolation
discussion (one shared resource, used by every tenant, with no per-tenant
cryptographic separation) - consistent with that doc's own point that this project
otherwise takes tenant isolation seriously (RBAC, `tenant_key`-scoped tables
everywhere) and this is the one place that discipline has a single shared secret
underneath it.

**STRIDE**: Elevation of Privilege / Spoofing, ranked high below precisely because
one compromise defeats every other tenant-isolation control at once.

## 7. Secrets handling (checked directly, a real positive finding)

- `deploy/lab/.env` is **gitignored** (`git check-ignore deploy/lab/.env` exit 0,
  confirmed) - real secrets are never committed.
- `docker-compose.yml` never hardcodes a secret - every credential is
  `${VAR:?set in deploy/lab/.env}`, a required-env-var reference, not a literal value
  (grepped the whole file: zero hardcoded passwords).

This is a working control, stated plainly as one rather than only listing gaps.

## 8. Rule/feed updates

**Does not exist as a real boundary yet** - confirmed in Item 5's inventory: no Sigma
rules, no YARA rules, no feed-update mechanism anywhere in this repo
(`shadowtracer/intel/`, `shadowtracer/vuln/` are empty directories; `VT_API_KEY` exists
in `.env` but is referenced by zero Python code). Nothing to threat-model today -
flagged so this gets a real pass **when** that mechanism is built, not forgotten
because this report found "nothing" and moved on.

## 9. Future SOAR

**Does not exist yet** - `shadowtracer/soar/` is an empty directory. Same note as §8.

## 10. Ranked top 10 (highest risk first)

1. **Kafka: plaintext, zero authentication, on every listener** (§3) - the widest-open
   boundary, and the one the tenant-isolation model (§6, `TENANCY.md`) most depends on
   being closed.
2. **Single shared `JWT_SECRET` for every tenant** (§6) - one compromise breaks
   cross-tenant isolation in one step, for every tenant at once.
3. **ClickHouse: one shared admin-equivalent credential, no per-service least
   privilege** (§4) - confirmed via an empty grep for any role/grant statement.
4. **Postgres/ClickHouse traffic is cleartext** (§4) - `ssl=off` confirmed directly;
   credentials and tenant data both exposed to anyone who can observe the network.
5. **Tenant identity is asserted by the shipper into an unauthenticated bus** (§3,
   compounding #1) - the thing that makes #1 specifically a tenant-isolation risk, not
   just a generic "internal traffic is cleartext" risk.
6. **No network segmentation** - every service shares one flat Docker network/subnet;
   a compromised shipper (which only needs to reach Kafka) can reach Postgres/
   ClickHouse directly with whatever shared credential it has (§4's finding compounds
   this - for ClickHouse, that's full admin access).
7. **`agent -> manager` not independently re-audited** (§1) - lower risk because it's
   upstream Wazuh's own hardened protocol, but "inherited and trusted, not re-checked"
   is itself worth naming as a residual risk, not a cleared one.
8. **No consolidated secrets rotation/expiry story** - `.env` values are generated
   once (per `deploy/lab/.env.example`'s own instructions) with no documented rotation
   process; not independently scored above the items with confirmed exploitability,
   but a real gap once this runs in production.
9. **Rule/feed update mechanism doesn't exist yet** (§8) - not a live risk today, ranked
   low specifically *because* nothing is there to attack yet, not because it's been
   secured.
10. **Future SOAR doesn't exist yet** (§9) - same reasoning as #9.

No fixes in this item, per instruction - this ranking is the input to whatever gets
prioritized next.
