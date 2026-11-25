"""Phase 9 (e): SOAR notifier — delivery to local mock servers (no real internet), minimal vs
standard detail, redaction (no secrets / raw logs in payloads), 429 retry-after, burst batching,
and disabled channels send nothing. A separate opt-in test targets real Discord/Telegram.
"""
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import text

from app.soar import notify
from conftest import insert_tenant

TK = "soar-notify-tenant"
NOW = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)


class _Mock:
    """A tiny local HTTP endpoint that records POST bodies and can be told to return 429."""
    def __init__(self):
        self.received = []
        self.status = 200
        self.retry_after = "2"
        box = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("content-length", 0))
                box.received.append(self.rfile.read(n).decode())
                self.send_response(box.status)
                if box.status == 429:
                    self.send_header("Retry-After", box.retry_after)
                self.end_headers()
                self.wfile.write(b"{}")

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()


@pytest.fixture
def mock():
    m = _Mock()
    yield m
    m.stop()


def _secrets(monkeypatch, tenant, mapping):
    monkeypatch.setenv("SOAR_CHANNEL_SECRETS", json.dumps({tenant: mapping}))


def _enable(db, channel, detail="minimal"):
    db.execute(text("INSERT INTO soar_channels (tenant_key, channel, enabled, detail_level) "
                    "VALUES (:t, :c, true, :d)"), {"t": TK, "c": channel, "d": detail})
    db.commit()


@pytest.mark.parametrize("channel,secret", [
    ("slack", {"webhook_url": "URL"}),
    ("discord", {"webhook_url": "URL"}),
    ("webhook", {"webhook_url": "URL"}),
    ("telegram", {"token": "T", "chat_id": "42", "api_base": "URL"}),
])
def test_http_channel_delivers_to_mock(db, monkeypatch, mock, channel, secret):
    insert_tenant(db, TK)
    sec = {k: (mock.url if v == "URL" else v) for k, v in secret.items()}
    _secrets(monkeypatch, TK, {channel: sec})
    _enable(db, channel)
    notify.enqueue(db, TK, "action_executed", {"incident_title": "inc 7", "severity": 3}, 3)
    assert notify.deliver_pending(db) == 1
    assert len(mock.received) == 1 and "inc 7" in mock.received[0]


def test_email_delivers_via_mock_smtp(db, monkeypatch):
    insert_tenant(db, TK)
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def send_message(self, msg): sent["subject"] = msg["Subject"]; sent["body"] = msg.get_content()

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    _secrets(monkeypatch, TK, {"email": {"to": "soc@x.io", "smtp_host": "localhost", "smtp_port": 25}})
    _enable(db, "email")
    notify.enqueue(db, TK, "action_executed", {"incident_title": "inc 9", "severity": 2}, 2)
    assert notify.deliver_pending(db) == 1
    assert "inc 9" in sent["body"]


def test_minimal_vs_standard_detail(db, monkeypatch, mock):
    insert_tenant(db, TK)
    _secrets(monkeypatch, TK, {"slack": {"webhook_url": mock.url}})
    _enable(db, "slack", detail="standard")
    notify.enqueue(db, TK, "action_executed",
                   {"incident_title": "inc 1", "severity": 5, "host": "agent-ubuntu-1",
                    "technique": "T1110", "action": "block_ip"}, 5)
    notify.deliver_pending(db)
    body = mock.received[0]
    assert "agent-ubuntu-1" in body and "T1110" in body          # standard includes host + technique


def test_redaction_drops_unsafe_fields(db, monkeypatch, mock):
    insert_tenant(db, TK)
    _secrets(monkeypatch, TK, {"slack": {"webhook_url": mock.url}})
    _enable(db, "slack", detail="standard")
    # unsafe fields (raw log line, a username from logs, a secret) must never reach the payload
    notify.enqueue(db, TK, "action_executed",
                   {"incident_title": "inc 1", "severity": 5,
                    "raw_log": "Nov 22 sshd: Failed password for root from 1.2.3.4",
                    "username": "root", "secret": "xoxb-TOKEN"}, 5)
    notify.deliver_pending(db)
    body = mock.received[0]
    assert "Failed password" not in body and "xoxb-TOKEN" not in body and "1.2.3.4" not in body


def test_429_is_retried_after_retry_after(db, monkeypatch, mock):
    insert_tenant(db, TK)
    _secrets(monkeypatch, TK, {"slack": {"webhook_url": mock.url}})
    _enable(db, "slack")
    notify.enqueue(db, TK, "action_executed", {"incident_title": "inc 1", "severity": 1}, 1)
    t0 = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=10)  # >= enqueue time
    mock.status = 429
    assert notify.deliver_pending(db, t0) == 0             # throttled, stays queued
    row = db.execute(text("SELECT status, retry_after_until FROM soar_notifications")).mappings().first()
    assert row["status"] == "queued" and row["retry_after_until"] == t0 + datetime.timedelta(seconds=2)
    assert notify.deliver_pending(db, t0 + datetime.timedelta(seconds=1)) == 0   # not yet due
    mock.status = 200
    assert notify.deliver_pending(db, t0 + datetime.timedelta(seconds=3)) == 1


def test_burst_is_batched_into_one_message(db, monkeypatch, mock):
    insert_tenant(db, TK)
    _secrets(monkeypatch, TK, {"slack": {"webhook_url": mock.url}})
    _enable(db, "slack")
    for i in range(50):
        notify.enqueue(db, TK, "action_executed", {"incident_title": f"inc {i}", "severity": 1}, 1)
    sent = notify.deliver_pending(db)
    assert sent == 50 and len(mock.received) == 1               # 50 events -> one summary POST
    assert "50 SOAR events" in mock.received[0]


def test_disabled_channel_sends_nothing(db, monkeypatch, mock):
    insert_tenant(db, TK)
    _secrets(monkeypatch, TK, {"slack": {"webhook_url": mock.url}})
    # channel row exists but disabled
    db.execute(text("INSERT INTO soar_channels (tenant_key, channel, enabled) VALUES (:t,'slack',false)"),
               {"t": TK})
    db.commit()
    queued = notify.enqueue(db, TK, "action_executed", {"incident_title": "x", "severity": 9}, 9)
    assert queued == 0 and notify.deliver_pending(db) == 0 and mock.received == []


def test_unconfigured_channel_is_not_queued(db, monkeypatch, mock):
    insert_tenant(db, TK)
    _secrets(monkeypatch, TK, {})                               # no secret for slack
    _enable(db, "slack")
    assert notify.enqueue(db, TK, "action_executed", {"incident_title": "x", "severity": 1}, 1) == 0


@pytest.mark.skipif(
    not __import__("os").environ.get("SOAR_MANUAL_NOTIFY_TEST"),
    reason="opt-in: set SOAR_MANUAL_NOTIFY_TEST=1 and SOAR_CHANNEL_SECRETS to hit real Discord/Telegram")
def test_manual_real_discord_telegram(db, monkeypatch):
    insert_tenant(db, TK)
    for ch in ("discord", "telegram"):
        if notify.is_configured(TK, ch):
            _enable(db, ch)
    notify.enqueue(db, TK, "test", {"incident_title": "ShadowTracer manual notify test", "severity": 1}, 1)
    print("sent:", notify.deliver_pending(db))
