"""SOAR notifications (Phase 9 e). Notification-only escalation to email / webhook / Slack / Discord /
Telegram (+ optional Shuffle webhook). Rules enforced here:

  - off by default, enabled per tenant by admin (soar_channels); every config change audited (router).
  - detail level per channel: minimal (severity, incident title, action status, console link) or
    standard (+ host, ATT&CK technique, action taken). NEVER raw logs, log usernames, secrets, or full
    IOC lists — the context is whitelisted to SAFE_KEYS at enqueue, so unsafe fields can't leak.
  - secrets (webhook URLs, bot token + chat id, SMTP) come ONLY from the environment
    (SOAR_CHANNEL_SECRETS JSON); never stored in the DB, logged, or returned by the API (which reports
    configured/not-configured).
  - delivery is queued (soar_notifications): retry with backoff, honour HTTP 429 Retry-After,
    per-channel throttle, and burst batching (many events within the window -> one summary). A delivery
    failure stays visible in the queue and NEVER blocks the action.

Messages link to the console/approval page; there are no inbound buttons or callbacks.
"""

import datetime
import json
import logging
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from itertools import groupby

import httpx
from sqlalchemy import func, select, text

from .models import soar_channels, soar_notifications

log = logging.getLogger("soar.notify")

CHANNELS = ("email", "webhook", "slack", "discord", "telegram", "shuffle")
HTTP_CHANNELS = {"webhook", "slack", "discord", "telegram", "shuffle"}
MAX_ATTEMPTS = 5
# Fields a message may ever contain. Anything else (raw logs, log usernames, IOC lists) is dropped.
SAFE_KEYS = {"incident_id", "incident_title", "severity", "action_status", "action",
             "host", "technique", "playbook", "console_base", "count"}
_MINIMAL_EXTRA = {"host", "technique", "action"}   # shown only at 'standard'


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


# ---- secrets (environment only) -------------------------------------------------------------------
def _all_secrets() -> dict:
    try:
        return json.loads(os.environ.get("SOAR_CHANNEL_SECRETS", "") or "{}")
    except json.JSONDecodeError:
        return {}


def channel_secret(tenant_key: str, channel: str) -> dict | None:
    """Per-tenant (falling back to '*') secret config for a channel, or None if not configured."""
    alls = _all_secrets()
    merged = {**(alls.get("*", {})), **(alls.get(tenant_key, {}))}
    sec = merged.get(channel)
    return sec or None


def is_configured(tenant_key: str, channel: str) -> bool:
    return channel_secret(tenant_key, channel) is not None


# ---- templates + redaction ------------------------------------------------------------------------
def _console_link(ctx: dict) -> str:
    base = (ctx.get("console_base") or "").rstrip("/")
    iid = ctx.get("incident_id")
    return f"{base}/#/incidents/{iid}" if iid else base


def render(event: str, detail_level: str, ctx: dict) -> tuple[str, str]:
    """-> (subject, body), containing only whitelisted fields for the detail level."""
    sev = ctx.get("severity", "?")
    title = ctx.get("incident_title", "incident")
    status = ctx.get("action_status", "")
    subject = f"[ShadowTracer] {event} — {title} (sev {sev})"
    lines = [f"Event: {event}", f"Severity: {sev}", f"Incident: {title}"]
    if status:
        lines.append(f"Action status: {status}")
    if detail_level == "standard":
        for k, label in (("host", "Host"), ("technique", "ATT&CK"), ("action", "Action")):
            if ctx.get(k):
                lines.append(f"{label}: {ctx[k]}")
    lines.append(f"Console: {_console_link(ctx)}")
    return subject, "\n".join(lines)


def render_batch(event_rows: list[dict], detail_level: str) -> tuple[str, str]:
    """One summary for a burst of events on a channel (burst batching)."""
    n = len(event_rows)
    sample = event_rows[0]["context"]
    subject = f"[ShadowTracer] {n} SOAR events"
    lines = [f"{n} SOAR events in the last window:"]
    for r in event_rows[:20]:
        c = r["context"]
        lines.append(f"- {r['event']}: {c.get('incident_title', 'incident')} (sev {c.get('severity', '?')})")
    lines.append(f"Console: {_console_link(sample)}")
    return subject, "\n".join(lines)


# ---- senders --------------------------------------------------------------------------------------
@dataclass
class SendResult:
    ok: bool
    retry_after: float | None = None     # seconds, from a 429
    error: str | None = None


def _http_result(resp: httpx.Response) -> SendResult:
    if resp.status_code == 429:
        ra = resp.headers.get("retry-after")
        try:
            secs = float(ra) if ra else 30.0
        except ValueError:
            secs = 30.0
        return SendResult(False, retry_after=secs, error="429 throttled")
    if 200 <= resp.status_code < 300:
        return SendResult(True)
    return SendResult(False, error=f"HTTP {resp.status_code}")


def _post(url: str, payload: dict) -> SendResult:
    try:
        with httpx.Client(timeout=10) as c:
            return _http_result(c.post(url, json=payload))
    except httpx.HTTPError as e:
        return SendResult(False, error=str(e))


def send_slack(sec: dict, subject: str, body: str) -> SendResult:
    return _post(sec["webhook_url"], {"text": f"*{subject}*\n{body}"})


def send_discord(sec: dict, subject: str, body: str) -> SendResult:
    return _post(sec["webhook_url"], {"content": f"**{subject}**\n{body}"})


def send_webhook(sec: dict, subject: str, body: str) -> SendResult:
    return _post(sec["webhook_url"], {"subject": subject, "body": body})


def send_shuffle(sec: dict, subject: str, body: str) -> SendResult:
    return _post(sec["webhook_url"], {"subject": subject, "body": body})


def send_telegram(sec: dict, subject: str, body: str) -> SendResult:
    base = sec.get("api_base", "https://api.telegram.org").rstrip("/")
    url = f"{base}/bot{sec['token']}/sendMessage"
    return _post(url, {"chat_id": sec["chat_id"], "text": f"{subject}\n{body}"})


def send_email(sec: dict, subject: str, body: str) -> SendResult:
    try:
        msg = EmailMessage()
        msg["From"] = sec.get("from", "shadowtracer@localhost")
        msg["To"] = sec["to"]
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(sec.get("smtp_host", "localhost"), int(sec.get("smtp_port", 25)), timeout=10) as s:
            if sec.get("username"):
                s.starttls()
                s.login(sec["username"], sec.get("password", ""))
            s.send_message(msg)
        return SendResult(True)
    except (OSError, smtplib.SMTPException) as e:
        return SendResult(False, error=str(e))


SEND_FNS = {"email": send_email, "webhook": send_webhook, "slack": send_slack,
            "discord": send_discord, "telegram": send_telegram, "shuffle": send_shuffle}


def incident_ctx(db, tenant_key: str, incident_id: int) -> dict:
    """Build a SAFE notification context from an incident — only non-sensitive fields (title is the
    incident id, never raw log content; technique is the ATT&CK id; host is the agent id)."""
    row = db.execute(text("SELECT priority, max_level, mitre_ids, agent_id FROM incidents "
                          "WHERE tenant_key=:t AND id=:i"),
                     {"t": tenant_key, "i": incident_id}).mappings().first()
    if not row:
        return {"incident_id": incident_id, "incident_title": f"incident {incident_id}", "severity": 0}
    mitre = row["mitre_ids"] or []
    return {
        "incident_id": incident_id,
        "incident_title": f"incident {incident_id}",
        "severity": row["priority"] if row["priority"] is not None else row["max_level"],
        "host": row["agent_id"],
        "technique": mitre[0] if mitre else None,
        "console_base": os.environ.get("SOAR_CONSOLE_BASE", ""),
    }


def notify_safe(db, tenant_key: str, event: str, ctx: dict, severity: int) -> None:
    """Enqueue, swallowing any error — a notification must NEVER block or fail the action it reports."""
    try:
        enqueue(db, tenant_key, event, ctx, severity)
    except Exception:                                        # noqa: BLE001
        log.exception("soar notify enqueue failed (event=%s) — action unaffected", event)


# ---- enqueue --------------------------------------------------------------------------------------
def enqueue(db, tenant_key: str, event: str, ctx: dict, severity: int = 0,
            only_channel: str | None = None) -> int:
    """Queue `event` to every enabled+configured channel whose severity threshold it clears. Returns
    the number of rows queued. The context is whitelisted here so no unsafe field can ever be sent."""
    safe = {k: v for k, v in ctx.items() if k in SAFE_KEYS}
    rows = db.execute(select(soar_channels).where(
        soar_channels.c.tenant_key == tenant_key, soar_channels.c.enabled.is_(True),
        soar_channels.c.min_severity <= severity)).mappings().all()
    queued = 0
    for ch in rows:
        if only_channel and ch["channel"] != only_channel:
            continue
        if not is_configured(tenant_key, ch["channel"]):
            continue
        db.execute(soar_notifications.insert().values(
            tenant_key=tenant_key, channel=ch["channel"], event=event, severity=severity, context=safe))
        queued += 1
    db.commit()
    return queued


# ---- delivery -------------------------------------------------------------------------------------
def _channel_cfg(db, tenant_key: str, channel: str) -> dict | None:
    row = db.execute(select(soar_channels).where(
        soar_channels.c.tenant_key == tenant_key, soar_channels.c.channel == channel)).mappings().first()
    return dict(row) if row else None


def _mark(db, ids: list[int], result: SendResult, now, attempts: int):
    if result.ok:
        db.execute(soar_notifications.update().where(soar_notifications.c.id.in_(ids))
                   .values(status="sent", sent_at=now))
        return
    if result.retry_after is not None:                       # 429: honour Retry-After, stay queued
        db.execute(soar_notifications.update().where(soar_notifications.c.id.in_(ids)).values(
            retry_after_until=now + datetime.timedelta(seconds=result.retry_after),
            next_attempt_at=now + datetime.timedelta(seconds=result.retry_after),
            attempts=attempts + 1, last_error=result.error))
        return
    new_attempts = attempts + 1
    if new_attempts >= MAX_ATTEMPTS:
        db.execute(soar_notifications.update().where(soar_notifications.c.id.in_(ids))
                   .values(status="failed", attempts=new_attempts, last_error=result.error))
    else:
        backoff = 2 ** new_attempts                          # exponential backoff
        db.execute(soar_notifications.update().where(soar_notifications.c.id.in_(ids)).values(
            attempts=new_attempts, last_error=result.error,
            next_attempt_at=now + datetime.timedelta(seconds=backoff)))


def deliver_pending(db, now=None, *, send_fns=None) -> int:
    """One delivery pass. Groups due queued rows per (tenant, channel); applies throttle and burst
    batching (>1 due on a channel -> one summary), sends, and records retry/backoff/429. Returns the
    number of notifications marked sent. Never raises for a send failure."""
    now = now or _utcnow()
    send_fns = send_fns or SEND_FNS
    due = db.execute(select(soar_notifications).where(
        soar_notifications.c.status == "queued",
        soar_notifications.c.next_attempt_at <= now,
        (soar_notifications.c.retry_after_until.is_(None)) | (soar_notifications.c.retry_after_until <= now)
    ).order_by(soar_notifications.c.tenant_key, soar_notifications.c.channel,
               soar_notifications.c.created_at)).mappings().all()

    sent = 0
    keyf = lambda r: (r["tenant_key"], r["channel"])
    for (tenant_key, channel), grp in groupby(due, key=keyf):
        rows = [dict(r) for r in grp]
        cfg = _channel_cfg(db, tenant_key, channel) or {}
        detail = cfg.get("detail_level", "minimal")
        sec = channel_secret(tenant_key, channel)
        if sec is None:
            _mark(db, [r["id"] for r in rows], SendResult(False, error="not configured"),
                  now, rows[0]["attempts"])
            continue

        # per-channel throttle: if sent within throttle_seconds, defer this group
        throttle = cfg.get("throttle_seconds", 0)
        if throttle:
            last = db.execute(select(func.max(soar_notifications.c.sent_at)).where(
                soar_notifications.c.tenant_key == tenant_key,
                soar_notifications.c.channel == channel,
                soar_notifications.c.status == "sent")).scalar()
            if last and (now - last).total_seconds() < throttle:
                db.execute(soar_notifications.update()
                           .where(soar_notifications.c.id.in_([r["id"] for r in rows]))
                           .values(next_attempt_at=last + datetime.timedelta(seconds=throttle)))
                continue

        if len(rows) > 1:                                    # burst batching: one summary for the group
            subject, body = render_batch(rows, detail)
        else:
            subject, body = render(rows[0]["event"], detail, rows[0]["context"])
        result = send_fns[channel](sec, subject, body)
        _mark(db, [r["id"] for r in rows], result, now, rows[0]["attempts"])
        if result.ok:
            sent += len(rows)
    db.commit()
    return sent
