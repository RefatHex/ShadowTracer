# Kafka authentication and tenant binding (Phase 5.6 Item 1)

Status: **implemented and verified.** §2's original recommendation (option b,
signed envelopes on a shared topic) was **not** what got built - the user
approved option (a), per-tenant topics, specifically so a cross-tenant produce
attempt is refused by the broker itself, not just detected downstream. See §4
for what's real now. This directly closes the #1 finding from
`docs/design/THREAT_MODEL.md`'s ranked top 10 ("Kafka: plaintext, zero
authentication, on every listener") and the follow-on #5 finding ("tenant
identity is asserted by the shipper into an unauthenticated bus").

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

## 3. What actually got approved and built: option (a), not (b)

The user's own decision, verbatim: implement option (a) - per-tenant topics
(`shadowtracer.t.<tenant_key>.alerts` / `.dead-letter`), TLS + SASL/SCRAM for every
client, broker-enforced per-component ACLs, consumers bound by topic-name pattern
rather than a shared topic. The signed-envelope idea (option b) was explicitly
rejected in favor of broker-level enforcement: a cross-tenant produce attempt must be
refused by Kafka itself, not merely detected by application code after the fact.

**Partitions: 3 per topic** (both alerts and dead-letter), not the old global 24.
Justification (replaces the old entry, which sized for every tenant sharing one
topic): headroom for 2 writer + 2 correlate replicas each needs at least 2 partitions
to split work at all; 3 (not 2) leaves the same "N+1 for an odd-replica split"
headroom the old 24-partition entry used. Per-tenant, under-provisioning ONE tenant's
blast radius is just that tenant, not the whole system, and a new tenant's own count
can be chosen fresh at onboarding against its real expected load, rather than guessed
once for every future tenant combined the way the old global 24 had to be. See
`deploy/lab/create-kafka-topics.sh`'s own comment for the full reasoning.

**Keying**: `agent_id` alone now (`shipper.py`) - tenant is the topic itself, not part
of the partition key, since the whole point of per-tenant topics is that tenant
identity no longer needs to ride inside message metadata to be trusted.

**Tenant identity model**: the topic a message was actually read from is the TRUSTED
identity everywhere downstream (ClickHouse rows, tenant-existence checks, dead-letter
routing) - never the message's own `tenant_id` header taken at face value, even though
the header is still sent and still checked. A header that's PRESENT but disagrees with
the topic it arrived on is dead-lettered as `tenant_topic_mismatch` - the one thing a
per-tenant producer ACL alone can't catch (a shipper can still write a false header
claim into its OWN tenant's topic). A MISSING header makes no claim to disagree with,
so it's not an error - same backward-compat stance as Item 4's missing
`envelope_version` header.

## 4. VERIFY - real evidence, run against the live lab

1. **Unauthenticated client rejected**: a plain `confluent_kafka.Producer` with no
   SASL config against the `SASL_SSL` EXTERNAL listener (127.0.0.1:9094) was refused
   outright - `Disconnected: connection closed by peer... after 1ms in state
   APIVERSION_QUERY` - the broker never even completes protocol negotiation with an
   unauthenticated client.
2. **Tenant A's shipper credential cannot land data as tenant B - refused by the
   broker**: the real `shipper` SCRAM credential (scoped to `TENANT_KEY`'s own two
   topics) attempting to produce to `TEST_TENANT_KEY`'s alerts topic got back
   `KafkaError{code=TOPIC_AUTHORIZATION_FAILED, val=29, str="Broker: Topic
   authorization failed"}` - the broker's ACL authorizer rejects the produce attempt
   before the message is ever written, not an application-level check after the
   fact. Confirmed `shipper` can still produce to its OWN topic (`err: None`,
   delivered to a real partition) and cannot even join a consumer group at all
   (`GROUP_AUTHORIZATION_FAILED` - no Group ACL was ever granted to a producer-only
   principal), proving the ACLs are real role separation, not a blanket grant.
3. **Full `smoke-test.sh`**: passed, including the Kafka-specific checks (all 12
   dead-letter writes landed on both ClickHouse replicas AND on the real per-tenant
   Kafka dead-letter topic; no pipeline container restarted; the main lab tenant
   received zero new incidents from this run's test traffic). Two unrelated FAILs
   found and confirmed pre-existing, not caused by this item: `agent-ubuntu-1`/`-2`
   lost their manager enrollment at some earlier point in this session's many
   `docker compose down` cycles (`wazuh-agentd: ERROR: Invalid password. Unable to
   add agent` in the agent's own log) - Wazuh agent enrollment, a completely
   different system from Kafka, never touched by this item. Flagged for separate
   follow-up, not fixed here.
4. **`verify-correlator-chaos.sh` and `verify-phase5b.sh`**: updated for per-tenant
   topics (topic names, keying, `owner_of_partition` now disambiguates by topic since
   partition numbers are no longer globally unique across tenants) and re-run with
   auth on - see `DECISIONS.md`'s Item 1 entry for the pass/fail detail.
5. **Full ingest/correlate/console-backend pytest suites**, updated for per-tenant
   topics (`kafka_topic`/`kafka_tenant_key` fixtures now provision a real tenant +
   topic pair per test, not an arbitrary shared name) and a shared broad `test` SCRAM
   credential (Read/Write/Describe/Create/Delete, scoped to this role only, never used
   by a real pipeline component) - see `DECISIONS.md` for the real pass counts.
