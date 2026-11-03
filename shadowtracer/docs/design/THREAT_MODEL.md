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

Phase 5.6 closeout status (see §12 for the decisions behind the #2/#7 changes
and the full before-first-customer plan): **#1/#5 done** (Item 1, this
session). **#2, #3, #6, #7: before first customer** - decided/specified now
(§12), not yet built. **#4: before multi-host**, not before first customer -
today's single-Docker-daemon deployment has no network segment for this
traffic to cross that the operator doesn't already control, so it's real but
not the most urgent gap for a first customer on the same topology as today's
lab. **#8: the runbook alone, now** (§12.3) - not the secrets-manager
integration its own "Higher effort" tier describes. **#9/#10: deferred**,
unchanged - still nothing built to secure.

1. **Kafka: plaintext, zero authentication, on every listener** (§3) - the widest-open
   boundary, and the one the tenant-isolation model (§6, `TENANCY.md`) most depends on
   being closed. **Done (Item 1)** - see `docs/design/KAFKA_AUTH.md`: TLS + SASL/SCRAM,
   per-tenant topics, per-component ACLs.
2. **Single shared `JWT_SECRET` for every tenant** (§6) - one compromise breaks
   cross-tenant isolation in one step, for every tenant at once. **Before first
   customer** - design revised in §12.1 (one EdDSA/RS256 pair + `kid`, not
   per-tenant keys - the per-tenant design below in §11 is superseded).
3. **ClickHouse: one shared admin-equivalent credential, no per-service least
   privilege** (§4) - confirmed via an empty grep for any role/grant statement.
   **Before first customer** - unchanged design from §11 item 3.
4. **Postgres/ClickHouse traffic is cleartext** (§4) - `ssl=off` confirmed directly;
   credentials and tenant data both exposed to anyone who can observe the network.
   **Before multi-host**, not before first customer (see status note above).
5. **Tenant identity is asserted by the shipper into an unauthenticated bus** (§3,
   compounding #1) - the thing that makes #1 specifically a tenant-isolation risk, not
   just a generic "internal traffic is cleartext" risk. **Done (Item 1)** - same fix
   as #1, signed envelopes / per-tenant topics close this specifically.
6. **No network segmentation** - every service shares one flat Docker network/subnet;
   a compromised shipper (which only needs to reach Kafka) can reach Postgres/
   ClickHouse directly with whatever shared credential it has (§4's finding compounds
   this - for ClickHouse, that's full admin access). **Before first customer** -
   unchanged design from §11 item 6.
7. **`agent -> manager` not independently re-audited** (§1) - lower risk because it's
   upstream Wazuh's own hardened protocol, but "inherited and trusted, not re-checked"
   is itself worth naming as a residual risk, not a cleared one. **Before first
   customer** - concrete decision made in §12.2 (keep the enrollment password, add
   agent-side manager certificate verification), replacing §11 item 7's "or an
   explicit documented decision to treat it as inherited" with that decision.
8. **No consolidated secrets rotation/expiry story** - `.env` values are generated
   once (per `deploy/lab/.env.example`'s own instructions) with no documented rotation
   process; not independently scored above the items with confirmed exploitability,
   but a real gap once this runs in production. **Runbook written now** (§12.3); the
   secrets-manager integration tier of §11 item 8 remains not scheduled.
9. **Rule/feed update mechanism doesn't exist yet** (§8) - not a live risk today, ranked
   low specifically *because* nothing is there to attack yet, not because it's been
   secured. **Deferred**, unchanged.
10. **Future SOAR doesn't exist yet** (§9) - same reasoning as #9. **Deferred**,
    unchanged.

No fixes in this item originally, per instruction - this ranking was the input to
whatever got prioritized next. §12 is that next step's decisions (doc-only, per Phase
5.6 Item 2 - no implementation yet except where §12 says otherwise).

## 11. Proposed fix and effort per top-10 item (Phase 5.6 Item 2 - report only)

No fixes implemented here except where noted (#1/#5 are already in progress as
Phase 5.6 Item 1 - `docs/design/KAFKA_AUTH.md`, not yet approved/built).

1. **Kafka plaintext/no auth.** Fix: `KAFKA_AUTH.md`'s design - TLS + SASL/SCRAM +
   per-component ACLs, signed envelopes for tenant binding. **Effort: Medium** -
   config and provisioning scripting across shipper/writer/correlator/console-backend,
   no new topics under the recommended option. **In progress (Item 1).**
2. **Single shared `JWT_SECRET`.** Fix: per-tenant signing keys (a new column on
   `tenants`, or HKDF-derived from one master key + `tenant_key`) - token issuance
   (`auth.py`) signs with the tenant's own key; verification (`rbac.py`) must decode
   the unverified claims first to learn `tenant_id`, look up that tenant's key, *then*
   verify the signature - a real implementation subtlety (reject firmly on algorithm/
   structure before any lookup, to avoid a downgrade attack), not just a config
   change. **Effort: Medium** - two files, one migration, and existing tokens need to
   expire/be reissued (short-lived tokens make this cheap to roll out).
3. **ClickHouse shared admin credential.** Fix: per-service ClickHouse users/roles
   with scoped grants, same pattern Postgres's `shadowtracer_app` role already proves
   out (writer: `INSERT` only on `events`/`dead_letter_events`; closer: scoped to
   `fingerprint_occurrences`; console-backend: `SELECT` only; shipper: `INSERT` only
   on `dead_letter_events`). **Effort: Medium** - `CREATE USER`/`GRANT` statements
   added to schema application, plus a credential per service in compose.
4. **Postgres/ClickHouse cleartext.** Fix: enable TLS on both (self-signed lab CA,
   same pattern already used for Kafka's and `wazuh-authd`'s certs); every service's
   connection config needs the new `sslmode=require`/`interface="https"` settings.
   **Effort: Medium-High** - cert provisioning plus touching every connecting
   service's config, real testing needed (a TLS misconfiguration fails closed, which
   is correct but means this can't be rolled out partially without breaking things).
5. **Tenant identity into an unauthenticated bus.** Same fix as #1 (signed
   envelopes close this specifically). **In progress (Item 1).**
6. **No network segmentation.** Fix: split the single flat `lab` Docker network into
   tiers (e.g. a data-plane network for Kafka/ClickHouse/Postgres reachable only by
   ingest/correlate/console-backend, separate from the manager/agent network;
   shippers bridge both since they need manager-local file access and Kafka). Compose
   supports multiple networks per service natively. **Effort: Medium** - topology
   change with real dependency-mapping risk; needs the full chaos/smoke suite rerun
   to prove nothing's connectivity silently broke.
7. **`agent -> manager` never independently re-audited.** Fix: a dedicated review of
   upstream Wazuh's enrollment/secure-channel cipher suite and protocol version
   against current practice - **or** an explicit documented decision to treat it as
   inherited/out-of-scope (this fork doesn't maintain that code). **Effort: Low** as
   a decision, but needs real security-review time to do properly, not a reflexive
   code change - flagged as a scoping question before an effort estimate for an
   actual fix means anything.
8. **No secrets rotation/expiry story.** Fix, minimum viable: a documented rotation
   runbook (how to rotate `CLUSTER_KEY`/`ENROLL_PASSWORD`/`CLICKHOUSE_PASSWORD`/
   `POSTGRES_PASSWORD`/`JWT_SECRET` without downtime, informed by #2's per-tenant-key
   design once built). **Effort: Low** for documentation; **Higher** if this becomes
   an actual secrets-manager integration (Vault or equivalent) rather than
   versioned `.env` values with a rotation script.
9. **Rule/feed update mechanism doesn't exist yet.** No fix proposed - nothing to
   secure until it's built (Phase 5C/5D). Revisit then.
10. **Future SOAR doesn't exist yet.** Same as #9 - revisit when built.

## 12. Phase 5.6 Item 2: revised decisions (doc only - no implementation yet)

Doc update only, per instruction - none of §12.1/§12.2 is built. §12.3 is itself
the deliverable (a runbook), not a pointer to one still to be written.

### 12.1 JWT: superseding item 2's per-tenant-key design

Confirmed today's actual implementation, not just the §6/§11 description:
`app/security.py:57` - `jwt.encode(payload, jwt_secret, algorithm="HS256")`;
`app/security.py:63` - `jwt.decode(token, jwt_secret, algorithms=["HS256"])`. One
symmetric secret, one pinned algorithm already (the decode call was never
alg-agile - `algorithms=["HS256"]` is a list with one fixed entry, not read from
the token's own header), so today's code is not vulnerable to the classic
alg-confusion downgrade (RS256-signed token re-presented as HS256, verified
against the public key as if it were an HMAC secret) for the simple reason that
there's no RS256 key anywhere yet for an attacker to retarget. That changes the
moment any asymmetric key exists in this system, which is exactly why the design
below pins the algorithm explicitly rather than relying on "there's nothing to
confuse it with" by accident.

**Superseded:** item 2's own proposed fix above (per-tenant HMAC keys, decode
unverified claims first to learn `tenant_id`, look up that tenant's key, then
verify) is **not** the design going forward - it was flagged there as having "a
real implementation subtlety," and on reflection that subtlety is the problem,
not a detail to get right carefully: any step that makes a security decision
(which key to verify against) from data that hasn't been verified yet is a
standing invitation to exactly the downgrade-attack shape §6 already named. A
per-tenant-keyed design doesn't need that step to exist at all if the dispatch
key is something the server already trusts before touching the token - but
simpler still is not needing dispatch at all.

**Decided instead: one EdDSA (Ed25519) key pair for the whole deployment**, not
per-tenant:

- **Asymmetric, not per-tenant-symmetric.** One private key signs every token
  (console-backend, the only issuer); verification can use the public half alone
  - useful if any other service ever needs to verify a token without holding
    signing power, though nothing does yet. Still one shared cryptographic
    identity across tenants, same as today's one `JWT_SECRET` - the thing this
    actually fixes is algorithm/key hygiene, not re-introducing per-tenant
    isolation at the JWT layer (`rbac.py`'s `tenant_id` claim scoping, §6's
    "real, working control," still carries that weight; unchanged).
- **`kid` (key ID) in the JWT header, for *rotation*, never for *dispatch*.**
  Verification holds a small, server-controlled allowlist of currently-valid
  `(kid -> public key)` pairs - normally one entry, briefly two during a
  rotation window (old key still accepted for tokens issued before the
  rotation, long enough for the longest-lived refresh token to expire). The
  `kid` is read from the token's header only to pick WHICH already-trusted key
  to verify against - never to look up something that then influences whether
  verification is attempted at all, and never read from the payload (the
  header is itself unverified too, but the allowlist it indexes into is fixed
  and small, not attacker-influenceable the way a per-tenant key lookup is).
- **Algorithm pinned, explicitly, at both ends.** `jwt.encode(..., algorithm="EdDSA")`
  and `jwt.decode(..., algorithms=["EdDSA"])` (PyJWT's decode already requires
  the caller to pass this list - today's code does; the fix is choosing EdDSA/
  RS256 deliberately going in, not an API change). `RS256` is the fallback if
  the eventual runtime's crypto stack doesn't support Ed25519 cleanly - either
  is fine, HS256 is not, once any public/private split exists for a `kid`
  rotation window to ever matter.
- **Private key lives outside the repo, outside `.env` as a literal value.** Not
  a new idea - `.env` is already gitignored (§7) - but a key pair's private half
  is higher-value than a password: mount it as a file (same pattern Kafka's own
  TLS material already uses - `generate-kafka-certs.sh`'s output, gitignored,
  generated per environment) and reference it by **path**, the same
  `_env_or_file()` convention `app/config.py` already has for `JWT_SECRET`/
  `APP_DB_PASSWORD` (`NAME_FILE` wins over `NAME` when both are set) - no new
  mechanism needed, just using the one that exists for the right kind of secret.
- **Never decode unverified claims to pick a key.** Stated once above as the
  specific thing wrong with the superseded design; restated here as the
  standing rule for whatever replaces this again someday: a `kid`-keyed
  allowlist is safe because the allowlist itself isn't derived from anything
  the token claims - any future redesign that *does* need per-tenant keys again
  must find a way to identify the tenant from something already trusted
  (the request's own authenticated context, not the token being verified) or
  this exact subtlety recurs.

**Effort:** Low-Medium - `app/security.py`'s two call sites, `app/config.py`'s
key-loading (mirrors existing `_env_or_file` pattern), one key-generation step
added to lab bootstrap, and a rotation procedure (§12.3). No new migration -
nothing about this touches `tenants` or any other table. Existing tokens are
short-lived (`access_token_ttl_seconds`, `app/config.py`) so the cutover is a
deploy, not a data migration.

### 12.2 agent -> manager (item 7): a concrete decision, not just "inherited"

Confirmed directly, not assumed: `entrypoint-agent.sh:128`'s `agent-auth` call
passes `-m`/`-p`/`-A`/`-P`/`-a` - never `-v <ca-cert-path>` (confirmed in
`agent-auth -h`'s own usage: `-v <path> Full path to CA certificate used to
verify the server`). The manager's own `ossec.conf` already ships
`<ssl_manager_cert>`/`<ssl_manager_key>` (confirmed in `etc/ossec.conf:256-257`)
- it presents a certificate - but nothing on the agent side checks it against
anything, so enrollment today trusts whoever answers on port 1515 by IP/
hostname alone. The enrollment *password* (`ENROLL_PASSWORD`, `<use_password>`
flipped on in `entrypoint-manager.sh`) is real and already required - this
doesn't replace it, it closes the gap the password alone doesn't cover: a
network-position attacker between agent and manager can't see the password in
transit (Wazuh's own enrollment channel is encrypted, §1), but *could* stand up
a fake manager, answer the agent's connection, and harvest whatever the agent
sends on the (unverified) assumption it's talking to the real one.

**Decided: keep the enrollment password as-is, add agent-side verification of
the manager's certificate.** Concretely: a CA for manager certificates (same
self-signed-lab-CA pattern `generate-kafka-certs.sh` already established for
Kafka, not a new mechanism), the manager's `sslmanager.cert` signed by it
instead of today's presumably-self-signed leaf, and `agent-auth`'s own `-v
<ca-cert-path>` pointed at that CA's public cert. An agent whose enrollment
fails closed against an unrecognized manager certificate is a real, if small,
improvement over today's "whoever answers" trust model - still explicitly
*not* a re-audit of Wazuh's underlying enrollment/secure-channel protocol
itself (that remains "inherited, not independently re-verified," §1/§7's
original framing, and stays out of scope here same as before).

**Effort:** Low - one CA generation step (reusing existing tooling), one
cert-signing change on the manager side, one new flag on the agent side. No
code change in either `entrypoint-manager.sh`'s structure or
`entrypoint-agent.sh`'s enrollment loop beyond that one flag.

### 12.3 Secrets rotation runbook (item 8 - the runbook itself, written now)

Scope: every credential this project generates into `deploy/lab/.env` as of
Phase 5.6 Item 1's closeout - the original item 8 list
(`CLUSTER_KEY`/`ENROLL_PASSWORD`/`CLICKHOUSE_PASSWORD`/`POSTGRES_PASSWORD`) plus
the SASL/SCRAM credentials Item 1 added (`KAFKA_ADMIN_PASSWORD`,
`KAFKA_SHIPPER_PASSWORD`, `KAFKA_SHIPPER_TEST_PASSWORD`,
`KAFKA_WRITER_PASSWORD`, `KAFKA_CORRELATOR_PASSWORD`,
`KAFKA_CONSOLE_BACKEND_PASSWORD`) and the JWT key pair from §12.1 once built.
Each generated with `openssl rand -base64 24` (passwords) as `.env.example`
already instructs, or a key-generation command (§12.1's key pair, once that
exists).

**Wazuh cluster/enrollment (`CLUSTER_KEY`, `ENROLL_PASSWORD`):**
1. Generate the new value (`openssl rand -base64 24` for `ENROLL_PASSWORD`;
   `CLUSTER_KEY` per Wazuh's own cluster-key format).
2. Roll the manager and every worker together (`docker compose up -d
   --force-recreate shadowtracer-master shadowtracer-worker1
   shadowtracer-worker2 shadowtracer-worker-test`) - `CLUSTER_KEY` must match
   across the whole cluster at all times, so this one has no zero-downtime
   path with today's single-key-per-cluster design; a brief cluster-rejoin
   window is expected.
3. `ENROLL_PASSWORD` only affects *new* enrollments (§12.2's enrollment step) -
   already-enrolled agents are unaffected, since their key material was issued
   at enrollment time, not re-checked against the current password on every
   connection. No agent restart needed for this one.

**ClickHouse / Postgres (`CLICKHOUSE_PASSWORD`, `POSTGRES_PASSWORD`,
`APP_DB_PASSWORD`):**
1. Create the new credential in ClickHouse/Postgres directly first (`ALTER
   USER ... IDENTIFIED BY`/`ALTER ROLE ... PASSWORD`) - both support changing a
   password without dropping the session-holding connections already open.
2. Update `.env`, then roll every connecting service in turn (writer,
   correlator, closer, shipper, console-backend) - each picks up the new value
   on its own restart; no need to restart all of them simultaneously, since the
   OLD credential keeps working until the database-side change in step 1,
   which should happen only once every connector is confirmed on the new value
   (reverse the order from how it reads above in practice: roll the services
   first against a database that still accepts BOTH old and new, confirm,
   *then* revoke the old one - most DBs support having two valid passwords
   mid-rotation only via two distinct role/user names, not two passwords on one
   role, so a real zero-downtime rotation here needs a short-lived second
   credential, not just this project's current one-password-per-role model).

**Kafka SASL/SCRAM (`KAFKA_ADMIN_PASSWORD` and the per-role passwords):**
1. `kafka-configs.sh --alter --add-config
   'SCRAM-SHA-512=[password=<new>]' --entity-type users --entity-name <role>`
   adds the new credential *alongside* the old one - SCRAM supports multiple
   valid passwords per principal natively, unlike the Postgres/ClickHouse case
   above. This is the one rotation in this list with a real zero-downtime path
   already built into the tooling being used.
2. Update `.env` and roll the affected service(s) - writer/writer-2 for
   `KAFKA_WRITER_PASSWORD`, etc.
3. Once every service using that role is confirmed on the new password,
   `--delete-config 'SCRAM-SHA-512'` the old credential entry (`kafka-configs.sh
   --describe --entity-type users` lists current entries per principal to
   confirm which to remove).

**JWT key pair (§12.1, once built):**
1. Generate the new Ed25519/RS256 pair with a new `kid`.
2. Deploy console-backend with BOTH keys in its verification allowlist (old
   `kid` still accepted, new one added) but signing switched to the new key -
   this is precisely what the `kid`-keyed allowlist in §12.1 exists to make
   safe.
3. Wait at least `access_token_ttl_seconds` + `refresh_token_ttl_seconds`
   (`app/config.py`) past the cutover - every token signed with the old key
   will have expired naturally - then remove the old `kid` from the allowlist
   and retire the old private key.

**Not covered by this runbook:** a secrets-manager integration (Vault or
equivalent) remains the "Higher effort" tier of item 8's original estimate,
unscheduled - this runbook is the "Low effort, versioned `.env` + manual steps"
tier, the one decided as sufficient before first customer.
