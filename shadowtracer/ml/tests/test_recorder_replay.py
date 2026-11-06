import datetime as dt
import json

import pytest

from conftest import FakeConn
from shadowtracer_ml import recorder, replay

XML = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4720</EventID>"
       "<TimeCreated SystemTime='2020-10-09T09:33:26.1234567Z'/></System><EventData><Data Name='TargetUserName'>x</Data>"
       "</EventData><RenderingInfo><Message>A user account was created.\r\n\tSubject:\tadmin</Message></RenderingInfo></Event>")


def test_run_ids_and_technique_validation(fake_conn):
    rid = recorder.start(fake_conn, "t", "atomic", "agent-ubuntu-1", technique="T1136.001", recorded_by="me")
    assert rid.startswith("atomic-") and "INSERT INTO attack_runs" in fake_conn.calls[0][0]
    p = fake_conn.calls[0][1]
    assert p["lab"] == "attack" and p["src"] == "atomic_linux" and p["tech"] == "T1136.001"
    with pytest.raises(Exception):
        recorder.start(fake_conn, "t", "atomic", "agent-ubuntu-1", technique="1136", recorded_by="me")


def test_normal_runs_are_benign(fake_conn):
    recorder.start(fake_conn, "t", "normal", "agent-ubuntu-1", technique="T1105", recorded_by="me")
    assert fake_conn.calls[0][1]["lab"] == "benign" and fake_conn.calls[0][1]["src"] == "normal_activity"


def test_caldera_import_stores_steps_without_commands(fake_conn):
    op = {"id": "op1", "name": "lab", "adversary": {"name": "Discovery"}}
    links = [{"id": "l1", "host": "agent-ubuntu-1", "decide": "2026-11-06T12:00:00Z", "finish": "2026-11-06T12:00:05Z",
              "status": 0, "command": "c2VjcmV0", "ability": {"technique_id": "T1082", "name": "System info", "tactic": "discovery"}}]
    recorder.import_caldera(fake_conn, "t", op, links)
    steps = [p for s, p in fake_conn.calls if "attack_run_steps" in s]
    assert steps[0]["t"] == "T1082" and "c2VjcmV0" not in json.dumps(steps, default=str)


def test_win_format_matches_agent():
    assert replay.win_format_event_string("a\r\n\tb:\tc\td") == "a   b: c\td"


def test_iter_xml_events_one_and_multi_line():
    lines = ["noise\n", XML + "\n", "<Event>\n", "<System/>\n", "</Event>\n"]
    evs = list(replay.iter_xml_events(lines))
    assert len(evs) == 2 and evs[1] == "<Event>\n<System/>\n</Event>"


def test_eventchannel_message_is_what_remoted_forwards():
    m = replay.eventchannel_message(XML, "002", "replay-x")
    assert m.startswith("f:[002] (replay-x) any->EventChannel:{")
    body = json.loads(m.split("EventChannel:", 1)[1])
    assert body["Message"] == "A user account was created.   Subject: admin" and "\n" not in body["Event"]


def test_original_time_kept():
    assert replay.original_time(XML) == dt.datetime(2020, 10, 9, 9, 33, 26, 123456, tzinfo=dt.timezone.utc)


def test_normal_activity_recover_aborts_cut_off_runs_and_undoes(monkeypatch):
    from shadowtracer_ml import normal_activity

    class Eng:
        def __init__(self):
            self.conn = FakeConn()

        def begin(self):
            import contextlib
            return contextlib.nullcontext(self.conn)
    eng, ran = Eng(), []
    normal_activity.recover(eng, execute=ran.append)
    assert "status = 'aborted'" in eng.conn.calls[0][0]
    assert "userdel svc-backup" in ran and "rm -f /etc/cron.d/st-logrotate" in ran


def test_evtx_xml_is_serialized_like_the_agent():
    x = '<Event xmlns="ns"><System><EventID Qualifiers="">1</EventID><Data Name="CommandLine">a "b" it\'s</Data></System></Event>'
    y = replay.agent_quotes(x)
    assert '"' not in y and "<EventID Qualifiers=''>1</EventID>" in y and "a &quot;b&quot; it's" in y
    assert "\\\"" not in replay.eventchannel_message(y, "1", "a").split('"Event":', 1)[1].replace('\\\\', '')
