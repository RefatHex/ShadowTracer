"""Phase 5B Step 5: campaign linking. Evaluated at incident CLOSE time
(closer.py), same place fingerprint computation and rare-pattern
evaluation already happen - in the same transaction, for the same
"mutable state in Postgres, nothing in memory" reasoning as everything
else in this phase.

Actor, defined explicitly (per the spec): the incident's primary source
IP (incidents.source_ips[0]) if it has one, else its primary user
(incidents.users[0]) if it has one, else no actor at all. An incident
correlated purely by rule_group (no source IP, no user ever recorded on
it) can never participate in campaign linking - there's no identity to
link by, and link_campaign returns None for it without creating or
touching anything.

Window: sliding, not a fixed total duration - a new incident links into
the most recent existing campaign for the same (tenant, fingerprint,
actor) if its first_seen is within 24h of that campaign's last_seen (the
most recently linked incident's own last_seen) - extending the
campaign's last_seen forward. A gap over 24h starts a brand new campaign
instead, NOT the same one, even for the identical fingerprint and actor -
this is what "same actor, same fingerprint, 25h apart -> NOT linked"
means in practice: the 25h-apart incident still gets its OWN campaign
row, it just isn't the same campaign as the earlier one.

Membership is idempotent via campaign_incidents' own unique constraint
(campaign_id, incident_id) - defensive, on top of the structural
guarantee that an incident can only ever close (and therefore only ever
call link_campaign) once, guarded by the same advisory lock closer.py
already uses for fingerprint computation.

Phase 5C Step 0b follow-up: closer.py processes incidents in whatever
order its SELECT returns them (close-eligibility order), not event-time
order, so an incident with an EARLIER first_seen can close (and reach
here) AFTER one with a LATER first_seen already created the campaign.
The window check below used to be a plain signed subtraction,
`(incident_first_seen - existing.last_seen) <= WINDOW` - for the
earlier-incident-closes-later case that difference is negative, and a
negative number is always <= a positive window regardless of magnitude,
so an incident truly days apart from the campaign's existing span would
still link, silently. Fixed with abs() - the same "checked on both
sides, not just forward" fix correlator.py's own session-gap matching
already uses for the identical class of problem. Also now extends
first_seen backward (min), not just last_seen forward (max) - the first
incident to be processed for a given campaign is not necessarily the
chronologically first one.
"""

import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .models import campaign_incidents, campaigns

CAMPAIGN_WINDOW_SECONDS = 24 * 3600


def determine_actor(source_ips: list, users: list):
    """Returns (actor_type, actor_value) - source IP first, then user,
    per the spec's explicit definition - or (None, None) if the incident
    has neither."""
    if source_ips:
        return "source_ip", source_ips[0]
    if users:
        return "user", users[0]
    return None, None


def link_campaign(
    db, tenant_key: str, fingerprint_key: str, incident_id: int,
    source_ips: list, users: list, incident_first_seen: datetime.datetime, incident_last_seen: datetime.datetime,
):
    """Returns the campaign id this incident was linked to (new or
    existing), or None if it has no actor to link by at all."""
    actor_type, actor_value = determine_actor(source_ips, users)
    if actor_type is None:
        return None

    existing = db.execute(
        select(campaigns)
        .where(
            campaigns.c.tenant_key == tenant_key,
            campaigns.c.fingerprint_key == fingerprint_key,
            campaigns.c.actor_type == actor_type,
            campaigns.c.actor_value == actor_value,
        )
        .order_by(campaigns.c.last_seen.desc())
        .limit(1)
        .with_for_update()
    ).mappings().first()

    within_window = (
        existing is not None
        and abs((incident_first_seen - existing["last_seen"]).total_seconds()) <= CAMPAIGN_WINDOW_SECONDS
    )

    if within_window:
        campaign_id = existing["id"]
        db.execute(
            campaigns.update().where(campaigns.c.id == campaign_id).values(
                first_seen=min(existing["first_seen"], incident_first_seen),
                last_seen=max(existing["last_seen"], incident_last_seen),
                incident_count=existing["incident_count"] + 1,
            )
        )
    else:
        campaign_id = db.execute(
            campaigns.insert().values(
                tenant_key=tenant_key, fingerprint_key=fingerprint_key,
                actor_type=actor_type, actor_value=actor_value,
                first_seen=incident_first_seen, last_seen=incident_last_seen, incident_count=1,
            ).returning(campaigns.c.id)
        ).scalar_one()

    db.execute(
        pg_insert(campaign_incidents)
        .values(campaign_id=campaign_id, incident_id=incident_id, tenant_key=tenant_key)
        .on_conflict_do_nothing(constraint="campaign_incidents_identity_unique")
    )

    return campaign_id
