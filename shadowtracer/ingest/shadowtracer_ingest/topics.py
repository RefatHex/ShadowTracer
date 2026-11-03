"""Phase 5.6 Item 1: per-tenant Kafka topic naming, shared by shipper.py,
writer.py, shadowtracer_correlate/consumer.py, and dead_letter.py - the
one place this convention is defined, so all four never drift apart on
it.

Each tenant gets its own topic pair: shadowtracer.t.<tenant_key>.alerts
(what used to be the single shared shadowtracer.events.raw) and
shadowtracer.t.<tenant_key>.dead-letter (what used to be the single
shared shadowtracer.events.dead-letter) - see docs/design/KAFKA_AUTH.md
for why this (option a) over signed envelopes on a shared topic
(option b): a Kafka ACL is resource-scoped, not content-scoped, so only
splitting the topic itself lets the BROKER refuse a cross-tenant produce
attempt outright, rather than merely detecting it after the fact.

Consumers (writer, correlator) subscribe to every tenant's alerts topic
at once via a regex pattern (ALERTS_TOPIC_PATTERN) - confluent_kafka/
librdkafka treats a subscribed topic string starting with "^" as a
regex, not a literal name. tenant_from_alerts_topic() recovers which
tenant a given message came from directly from the topic it was read
from - the identity a per-tenant ACL already made trustworthy - which is
the identity used everywhere downstream (ClickHouse rows, dead-letter
routing), never the message's own tenant_id header taken at face value.
"""

import re

TOPIC_PREFIX = "shadowtracer.t."
ALERTS_SUFFIX = ".alerts"
DEAD_LETTER_SUFFIX = ".dead-letter"

# Matches shadowtracer.t.<anything>.alerts/.dead-letter, capturing
# <anything> as the tenant key - tenant keys are validated at creation
# (tenants.py) to already exclude "." (sql-identifier-safe), so this
# can't misparse a tenant key that itself contains the literal string
# ".alerts"/".dead-letter".
_ALERTS_TOPIC_RE = re.compile(r"^shadowtracer\.t\.(.+)\.alerts$")
_DEAD_LETTER_TOPIC_RE = re.compile(r"^shadowtracer\.t\.(.+)\.dead-letter$")

# The literal regex librdkafka subscribes to (leading "^" is what marks
# a subscribed topic string as a pattern rather than an exact name).
ALERTS_TOPIC_PATTERN = r"^shadowtracer\.t\..+\.alerts$"
DEAD_LETTER_TOPIC_PATTERN = r"^shadowtracer\.t\..+\.dead-letter$"


def alerts_topic_for_tenant(tenant_key: str) -> str:
    return f"{TOPIC_PREFIX}{tenant_key}{ALERTS_SUFFIX}"


def dead_letter_topic_for_tenant(tenant_key: str) -> str:
    return f"{TOPIC_PREFIX}{tenant_key}{DEAD_LETTER_SUFFIX}"


def tenant_from_alerts_topic(topic: str) -> str | None:
    """None if `topic` doesn't match the per-tenant alerts naming
    convention at all - callers treat that as a hard error (a consumer
    pattern-subscribed to ALERTS_TOPIC_PATTERN should never see a topic
    that fails this), not a recoverable one."""
    m = _ALERTS_TOPIC_RE.match(topic)
    return m.group(1) if m else None


def tenant_from_dead_letter_topic(topic: str) -> str | None:
    m = _DEAD_LETTER_TOPIC_RE.match(topic)
    return m.group(1) if m else None
