# Kafka authentication and tenant binding (Phase 5.6 Item 1)

Status: **design only, report and stop for approval.** Nothing implemented. This
directly closes the #1 finding from `docs/design/THREAT_MODEL.md`'s ranked top 10
("Kafka: plaintext, zero authentication, on every listener") and the follow-on #5
finding ("tenant identity is asserted by the shipper into an unauthenticated bus").

## 0. Baseline facts (real, checked against the running lab)

- `shadowtracer.events.raw`: 24 partitions, replication factor 1 in the lab (3 in
  production per `docs/DECISIONS.md`), keyed `tenant_key:agent_id`.
- Current broker config, confirmed directly
  (`docker exec shadowtracer-lab-kafka-1 cat /opt/kafka/config/server.properties`):
  `listener.security.protocol.map=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT`
  - every listener plaintext, no SASL, no ACL authorizer configured at all.
- `kafka-acls.sh` and `kafka-configs.sh` (for SCRAM credential provisioning) are both
  present in the `apache/kafka:3.9.0` image already in use - confirmed directly, not
  assumed. KRaft mode supports SASL/SCRAM, mTLS, and the standard ACL authorizer
  without needing ZooKeeper (which this project doesn't run anyway, per
  `docs/DECISIONS.md`'s Kafka decision).
- All producers/consumers in this codebase (`shipper.py`, `writer.py`,
  `shadowtracer_correlate/consumer.py`) use `confluent_kafka` (librdkafka) - confirmed
  by reading the actual `Producer(...)`/`Consumer(...)` call sites. librdkafka natively
  supports `security.protocol`, `sasl.mechanisms`, `sasl.username`/`sasl.password`,
  and `ssl.ca.location`/`ssl.certificate.location`/`ssl.key.location` - this is
  configuration, not a library change.

## 1. Baseline, applies regardless of which tenant-binding option is chosen

**TLS on every listener.** Terminates the current fully-plaintext state - the broker
gets a certificate (self-signed CA for the lab, same pattern already used for
`wazuh-authd`'s cert per `docs/DECISIONS.md`'s Phase 2 Pass B entry; a real CA in
production), every listener (`PLAINTEXT` and `EXTERNAL`) becomes `SASL_SSL`.

**SASL/SCRAM for client authentication**, not mTLS, as the default: SCRAM credentials
are simpler to provision per-component at this project's current scale (one
`kafka-configs.sh --alter --add-config 'SCRAM-SHA-256=[password=...]'` call per
shipper/writer/correlator instance, scriptable) than running a private CA that issues
and rotates per-client certificates. mTLS is the natural upgrade once client count or
compliance requirements justify a CA - not recommended to build now, same reasoning
`TENANCY.md` already used for deferring option (B) there.

**Per-component ACLs** (`kafka-acls.sh`), one credential class per role:
- Shipper credentials: `--producer` only, on `shadowtracer.events.raw` and
  `shadowtracer.events.dead-letter` - never `--consumer`. A compromised shipper
  cannot read any tenant's data back out of Kafka, including its own.
- Writer/correlator credentials: `--consumer` only, on both topics, scoped to their
  real consumer groups (`shadowtracer-writer`, `shadowtracer-correlate`) - never
  `--producer` on `events.raw` (they only ever produce to the dead-letter topic,
  which gets its own narrower producer grant).
- Console-backend credential: `--consumer` only, no group restriction needed since it
  reads ad hoc (health checks), never joins the real consumer groups.

This alone (TLS + SASL + role-scoped ACLs) stops an unauthenticated client from
reaching the broker at all, and stops a credential with the wrong role from doing the
wrong thing (a shipper consuming, a writer producing to the raw topic) - but **it does
not, by itself, stop shipper A's own valid producer credential from writing a message
whose `tenant_id` header claims to be tenant B**, since Kafka ACLs are
resource-scoped (topic/group), not message-content-scoped. That's what §2 solves.

## 2. Tenant binding: two options, compared

### (a) Per-tenant topics with ACLs

Each tenant gets its own topic (`shadowtracer.events.raw.<tenant_key>`). Each
shipper's SASL credential gets a `--producer` ACL scoped to *only its own tenant's*
topic name - Kafka's authorizer rejects a produce attempt to any other tenant's topic
outright, before the message is ever written. Writer/correlator credentials get a
`--consumer` ACL on a topic *pattern* (`--resource-pattern-type PREFIXED --topic
shadowtracer.events.raw.`), so onboarding a new tenant never requires touching their
grant.

- **Security**: strongest available - enforced by the broker's authorizer, not
  application code. A compromised shipper physically cannot write to another
  tenant's topic; there is no code path to get this wrong.
- **Ops cost**: scales with tenant count. Every new tenant is a new topic (plus,
  typically, its own partition-count decision) and a new producer ACL to provision -
  today that's a scripted `kafka-topics.sh --create` + `kafka-acls.sh --add` pair, not
  a manual step, but it is genuinely more infrastructure per tenant than option (b).
- **24-partition keying**: breaks the current single-topic model outright. Each
  per-tenant topic needs its own partition count - a small tenant doesn't need 24
  partitions (over-provisioning the common case), a very large tenant might need more
  than 24 (under-provisioning the outlier). This is a real, separate sizing decision
  per tenant, not a one-time global choice like today.
- **Consumer groups**: writer/correlator already use `confluent_kafka`'s
  subscribe-by-pattern (regex topic subscription is a standard librdkafka feature,
  not new code) - functionally fine, but every tenant's partitions now count toward
  *the same* two consumer groups' total partition count across *many* topics instead
  of one, which changes how Kafka's own partition-assignment/rebalance protocol
  behaves under topic churn (a new tenant's topic appearing mid-run triggers a
  rebalance across all partitions, not just the new ones) - not evaluated further
  here, flagged as a real operational wrinkle.
- **Replay**: *better* than today for per-tenant granularity - replaying one tenant's
  gap (per `docs/design/BACKUP_RESTORE.md`'s §1 consistency approach) means resetting
  one topic's consumer offset, not filtering a shared topic by tenant.
- **Dead-letter**: same choice recurses - either one shared dead-letter topic
  (simpler, but then it needs its own separate ACL story since it's no longer
  naturally tenant-scoped) or per-tenant dead-letter topics too (consistent, but
  doubles the new-topic-per-tenant cost).

### (b) Signed envelopes with per-shipper keys

Keep today's single shared topic, partitioning, and consumer groups entirely
unchanged. Each shipper is issued a per-shipper HMAC signing key at provisioning time
(alongside its existing static `TENANT_ID`, same operational moment). The shipper adds
a new Kafka header, `tenant_sig`: an HMAC-SHA256 over (`tenant_id` + `agent_id` +
`envelope_version`, see Item 4) using its own key. The writer and correlator - which
already both independently look up tenant state via `tenants.py`'s `TenantCache`,
per `docs/DECISIONS.md`'s Phase 5C Step 0 entry - look up the *expected* signing key
for the claimed `tenant_id` (a new column on the `tenants` table, or a separate
`tenant_signing_keys` table) and recompute the HMAC; a mismatch means the message's
`tenant_id` claim is not trustworthy, and it is dead-lettered with a clear,
new reason (`error="tenant_signature_mismatch"`) rather than trusted.

- **Security**: strong for the specific property asked for ("a shipper credential for
  tenant A cannot produce data that lands as tenant B") - a shipper that doesn't hold
  tenant B's signing key cannot forge a valid signature for tenant B, so its message
  gets dead-lettered, never processed as tenant B's data. Weaker than (a) in one
  specific sense: a compromised shipper *can* still successfully write garbage (or a
  flood) to the shared topic under its own valid tenant claim - option (a)'s
  broker-level topic isolation prevents cross-tenant writes at the infrastructure
  layer; option (b) prevents cross-tenant data from being *trusted downstream*, via
  application-level verification. For this specific attack ("can tenant A spoof
  tenant B"), both options fully solve it; option (a) additionally contains a
  compromised shipper's blast radius to its own topic, which (b) does not.
- **Ops cost**: low, and doesn't grow with tenant count - one signing key issued per
  shipper, stored and rotated the same way `TENANT_ID` already is today. No new
  topics, no per-tenant ACL provisioning.
- **24-partition keying, consumer groups, replay, dead-letter**: all **unchanged**.
  This is the direct advantage over (a) - zero architectural disruption to everything
  Phase 3/5A-5C already built, tested, and verified (the dedup/rollup/campaign-linking
  work, the chaos tests, the backup/restore replay story).

### Recommendation

**Option (b)**, for the same reason `docs/design/TENANCY.md` recommended keeping
today's dedicated-manager tenancy model: there is no production tenant count yet to
justify option (a)'s real, scaling ops cost and architectural disruption, and option
(b) fully closes the specific gap this item is about (`THREAT_MODEL.md` finding #5 -
tenant identity asserted into an unauthenticated bus) without touching anything the
backup/restore and versioning work already depends on. Revisit option (a) specifically
if/when per-tenant Kafka-level blast-radius containment becomes a real requirement
(e.g. a compliance or customer-contract need for hard infrastructure isolation, not
just data-integrity binding) - the same kind of condition `TENANCY.md`'s own option
(B) revisit note already names.

## 3. VERIFY plan (after approval, not run yet)

1. **Unauthenticated client rejected**: attempt a plain `confluent_kafka.Producer`
   connection with no SASL config against the `SASL_SSL` listener; expect a real
   connection/auth failure, captured directly.
2. **Tenant A's shipper credential cannot land data as tenant B**: run a real shipper
   process with tenant A's credentials and signing key, but a forged `tenant_id`
   header claiming tenant B (no valid signature for B) - confirm the message is
   dead-lettered with `tenant_signature_mismatch`, not processed as tenant B's data,
   and that zero rows land in tenant B's incidents/events.
3. **Full `smoke-test.sh` and the chaos tests** (`verify-correlator-chaos.sh`,
   `verify-phase5b.sh`) pass with auth fully on - proving this doesn't silently break
   the failover/rebalance behavior those scripts already exercise.

Waiting for approval before any implementation. Continuing with Items 2-10 in the
meantime, per instruction.
