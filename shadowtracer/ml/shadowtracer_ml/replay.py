"""Replay recorded public datasets through the TEST tenant's manager as if a Windows agent had
sent them (Phase 7.0, docs/ML_FOUNDATION.md "Recorded datasets").

Injection point: analysisd's queue socket `queue/sockets/queue` (DEFAULTQUEUE,
src/headers/defs.h:120), the socket remoted forwards every agent event to. remoted builds the
agent header "[id] (name) ip" (src/remoted/secure.c) and the message is
"<queue char>:[id] (name) ip-><location>:<log>". A Windows agent's EventChannel event uses
queue char 'f' (WIN_EVT_MQ, src/headers/mq_op.h), location "EventChannel" and the log
{"Message": <rendered text>, "Event": <the event XML>} after win_format_event_string()
(src/logcollector/read_win_event_channel.c, logcollector.c:1139). analysisd routes 'f' to its
EventChannel decoder (src/analysisd/analysisd.c:1377, decoders/winevtchannel.c), which builds
win.system / win.eventdata, and the inherited 0575/0580/0595 rules match as for a live agent.

Each dataset gets a DEDICATED replay agent (registered on the test manager, never a real
host). Events are re-timed to now (the alert time is when analysisd receives them); the
original time stays inside the event XML (win.system.systemTime) and in ClickHouse
ml_replay_events with the dataset id and ATT&CK label. Rate <= 200 events/s; aborts if the
host's MemAvailable drops below 1.5 GB.
"""
import datetime as dt
import hashlib
import json
import re
import subprocess
import time

from sqlalchemy import text

from . import db, recorder

MANAGER = "shadowtracer-lab-shadowtracer-worker-test-1"
MAX_RATE = 200
MIN_MEM_AVAILABLE_MB = 1536
_SYSTEM_TIME = re.compile(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]")
_RENDERED = re.compile(r"<Message>(.*?)</Message>", re.S)
# The sender inside the manager container (its framework Python): one datagram per line.
_SENDER = ("import socket,sys\n"
           "s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);s.connect('/var/ossec/queue/sockets/queue')\n"
           "for l in sys.stdin.buffer:\n"
           " l=l.rstrip(b'\\n')\n"
           " l and s.send(l)\n")


def win_format_event_string(xml: str) -> str:
    """Same transformation as the Windows agent (logcollector.c:1139): CR/LF -> space, and tabs
    that follow a CR/LF or ':' -> space."""
    out, i, n = [], 0, len(xml)
    while i < n:
        c = xml[i]
        if c in "\r\n:":
            out.append(" " if c in "\r\n" else c)
            i += 1
            while i < n and xml[i] == "\t":
                out.append(" ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def iter_xml_events(lines):
    """Windows events as XML, one per event, from Splunk XmlWinEventLog files (one event per
    line, or an event spread over several lines)."""
    buf = []
    for line in lines:
        if not buf and "<Event" not in line:
            continue
        buf.append(line.rstrip("\n"))
        if "</Event>" in line:
            yield "\n".join(buf)
            buf = []


def eventchannel_message(xml: str, agent_id: str, agent_name: str) -> str:
    rendered = _RENDERED.search(xml)
    log = json.dumps({"Message": win_format_event_string(rendered.group(1)) if rendered else "",
                      "Event": win_format_event_string(xml)}, separators=(",", ":"))
    location = f"[{agent_id}] ({agent_name}) any->EventChannel"
    return f"f:{location.replace('|', '||')}:{log}"


def original_time(xml: str):
    """The event's own time (<TimeCreated SystemTime='2020-10-09T09:33:26.1234567Z'/>), UTC."""
    m = _SYSTEM_TIME.search(xml)
    if not m:
        return None
    t = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?", m.group(1))
    if not t:
        return None
    frac = (t.group(2) or ".0")[:7]                     # Windows writes 7 digits; Python takes 6
    return dt.datetime.fromisoformat(t.group(1) + frac).replace(tzinfo=dt.timezone.utc)


# NXLog/Logstash fields OTRF adds around the event; everything else is the event's EventData.
_OTRF_META = {"Keywords", "SeverityValue", "EventID", "ProviderGuid", "ExecutionProcessID", "Channel", "host", "AccountType",
              "UserID", "ThreadID", "EventType", "Opcode", "EventTime", "EventReceivedTime", "@timestamp", "SourceModuleType",
              "port", "AccountName", "RecordNumber", "Task", "Domain", "@version", "OpcodeValue", "SourceModuleName", "Severity",
              "SourceName", "Version", "Category", "Hostname", "tags", "Message", "Level", "ActivityID", "RelatedActivityID",
              "ERROR_EVT_UNRESOLVED", "EventTypeOrignal"}


def _x(v) -> str:
    from xml.sax.saxutils import escape
    return escape(str(v), {"'": "&apos;", '"': "&quot;"})


def otrf_event_xml(rec: dict):
    """An OTRF (NXLog JSON) Windows record rebuilt as the event XML an agent would read, or None."""
    if "EventID" not in rec or "Channel" not in rec or "SourceName" not in rec:
        return None
    ts = str(rec.get("@timestamp") or "").replace(" ", "T")
    data = "".join(f"<Data Name='{_x(k)}'>{_x(v)}</Data>" for k, v in rec.items()
                   if k not in _OTRF_META and not k.startswith("@") and not isinstance(v, (dict, list)))
    msg = f"<RenderingInfo Culture='en-US'><Message>{_x(rec['Message'])}</Message></RenderingInfo>" if rec.get("Message") else ""
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<Provider Name='{_x(rec['SourceName'])}' Guid='{_x(rec.get('ProviderGuid', ''))}'/>"
            f"<EventID>{int(rec['EventID'])}</EventID><Version>{_x(rec.get('Version', 0))}</Version>"
            f"<Level>{_x(rec.get('SeverityValue', 4))}</Level><Task>{_x(rec.get('Task', 0))}</Task>"
            f"<Opcode>{_x(rec.get('OpcodeValue', 0))}</Opcode><Keywords>0x{int(rec.get('Keywords') or 0) & 0xFFFFFFFFFFFFFFFF:x}</Keywords>"
            f"<TimeCreated SystemTime='{_x(ts)}'/><EventRecordID>{_x(rec.get('RecordNumber', 0))}</EventRecordID>"
            f"<Execution ProcessID='{_x(rec.get('ExecutionProcessID', 0))}' ThreadID='{_x(rec.get('ThreadID', 0))}'/>"
            f"<Channel>{_x(rec['Channel'])}</Channel><Computer>{_x(rec.get('Hostname', ''))}</Computer>"
            f"<Security UserID='{_x(rec.get('UserID', ''))}'/></System><EventData>{data}</EventData>{msg}</Event>")


def iter_otrf(path: str):
    import zipfile
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            with z.open(name) as f:
                for line in f:
                    try:
                        xml = otrf_event_xml(json.loads(line))
                    except (ValueError, TypeError):
                        continue
                    if xml:
                        yield xml


_TAG = re.compile(r"(<[^>]+>)")
_DQ_ATTR = re.compile(r'(\s[\w:.-]+)="([^"]*)"')


def agent_quotes(xml: str) -> str:
    """Serialize like the Windows agent (EvtRender): attributes in single quotes, no raw '"'.
    analysisd parses the JSON-printed Event string (decoders/winevtchannel.c:152-155), where a
    '"' becomes '\\"' and the XML no longer parses - python-evtx writes double quotes."""
    out = []
    for part in _TAG.split(xml):
        if part.startswith("<"):
            out.append(_DQ_ATTR.sub(lambda m: f"{m.group(1)}='{m.group(2).replace(chr(39), '&apos;')}'", part))
        else:
            out.append(part.replace('"', "&quot;"))
    return "".join(out)


def iter_evtx(path: str):
    """EVTX records as event XML (python-evtx); used for EVTX-ATTACK-SAMPLES (GPL-3.0, internal only)."""
    import Evtx.Evtx as evtx
    with evtx.Evtx(path) as log:
        for rec in log.records():
            try:
                yield agent_quotes(rec.xml())
            except Exception:  # noqa: BLE001 - a corrupt record is skipped, the rest of the file replays
                continue


def iter_splunk(path: str):
    with open(path, encoding="utf-8", errors="replace") as f:
        for xml in iter_xml_events(f):
            yield agent_quotes(xml)


READERS = {"splunk": iter_splunk, "otrf": iter_otrf, "evtx": iter_evtx}


def mem_available_mb() -> int:
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return 1 << 30


def replay_agent(conn, tenant: str, dataset_id: str, manager: str = MANAGER) -> tuple:
    """A dedicated, registered agent per dataset ("replay-<slug>"); never a real host."""
    row = conn.execute(text("SELECT agent_id, agent_name FROM replay_agents WHERE tenant_key = :t AND dataset_id = :d"),
                       {"t": tenant, "d": dataset_id}).first()
    if row:
        return row[0], row[1]
    slug = re.sub(r"[^a-z0-9]+", "-", dataset_id.lower()).strip("-")[:40]
    name = f"replay-{slug}"
    subprocess.run(["docker", "exec", manager, "/var/ossec/bin/manage_agents", "-a", "any", "-n", name],
                   check=True, capture_output=True)
    listing = subprocess.run(["docker", "exec", manager, "/var/ossec/bin/manage_agents", "-l"],
                             check=True, capture_output=True, text=True).stdout
    m = re.search(rf"ID:\s*(\d+),\s*Name:\s*{re.escape(name)},", listing)
    if not m:
        raise RuntimeError(f"replay agent {name} not found after registration")
    conn.execute(text("INSERT INTO replay_agents (agent_id, agent_name, tenant_key, dataset_id) VALUES (:i, :n, :t, :d)"),
                 {"i": m.group(1), "n": name, "t": tenant, "d": dataset_id})
    return m.group(1), name


def replay(engine, ch, dataset_id: str, technique: str, files: list, rate: float = MAX_RATE,
           manager: str = MANAGER, mem_floor_mb: int = MIN_MEM_AVAILABLE_MB, fmt: str = "splunk", test_name: str = None) -> dict:
    rate = min(rate, MAX_RATE)
    tenant = db.test_tenant()
    with engine.begin() as conn:
        agent_id, agent_name = replay_agent(conn, tenant, dataset_id, manager)
        run_id = recorder.start(conn, tenant, "replay", agent_name, technique=technique, test_name=test_name or dataset_id,
                                source=f"replay:{dataset_id}", dataset_id=dataset_id, recorded_by="replay",
                                details={"files": [f.rsplit("/", 1)[-1] for f in files], "agent_id": agent_id})
    proc = subprocess.Popen(["docker", "exec", "-i", manager, "/var/ossec/framework/python/bin/python3", "-c", _SENDER],
                            stdin=subprocess.PIPE)
    sent, meta, t0, aborted = 0, [], time.monotonic(), None
    try:
        for path in files:
            for xml in READERS[fmt](path):
                if sent % int(rate) == 0 and mem_available_mb() < mem_floor_mb:
                    aborted = f"MemAvailable below {mem_floor_mb} MB"
                    break
                proc.stdin.write(eventchannel_message(xml, agent_id, agent_name).encode() + b"\n")
                meta.append([run_id, dataset_id, sent, agent_id, technique or "", original_time(xml),
                             dt.datetime.now(dt.timezone.utc), hashlib.sha256(xml.encode()).hexdigest()])
                sent += 1
                ahead = sent / rate - (time.monotonic() - t0)
                if ahead > 0:
                    proc.stdin.flush()
                    time.sleep(ahead)
            if aborted:
                break
    finally:
        proc.stdin.close()
        proc.wait(timeout=60)
        if meta:
            ch.insert("ml_replay_events", meta, column_names=["run_id", "dataset_id", "seq", "agent_id", "technique",
                                                               "original_time", "injected_at", "line_sha256"])
        with engine.begin() as conn:
            recorder.stop(conn, run_id, aborted=bool(aborted))
    return {"run_id": run_id, "dataset_id": dataset_id, "agent": f"{agent_id} {agent_name}", "events": sent,
            "seconds": round(time.monotonic() - t0, 1), "aborted": aborted}


def plan(data_dir: str = None) -> list:
    """Every usable recorded dataset: (dataset_id, technique, fmt, files, test_name). One dataset =
    one dedicated replay agent = one run, so no incident mixes two datasets."""
    import glob
    import os
    from . import datasets
    d = data_dir or datasets.ST_DATA
    out = []
    by_t = {}
    for f in sorted(glob.glob(os.path.join(d, "splunk", "win", "T*_*.log"))):
        by_t.setdefault(os.path.basename(f).split("_", 1)[0], []).append(f)
    for t, files in sorted(by_t.items()):
        out.append((f"splunk:{t}/atomic_red_team", t, "splunk", files, None))
    for meta in sorted(glob.glob(os.path.join(d, "otrf", "meta", "*.yaml"))):
        text_ = open(meta).read()
        link = re.search(r"link:\s*(\S+/host/(\S+\.zip))", text_)
        tm = re.search(r"technique:\s*(T\d{4})\s*\n\s*sub-technique:\s*\"?(\d{3})?", text_)
        zp = os.path.join(d, "otrf", "host", link.group(2)) if link else None
        if zp and os.path.exists(zp):
            tech = (tm.group(1) + (f".{tm.group(2)}" if tm.group(2) else "")) if tm else None
            out.append((f"otrf:{os.path.basename(meta)[:-5]}", tech, "otrf", [zp], link.group(2)[:-4]))
    root = os.path.join(d, "evtx-attack-samples")
    for tactic in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        files = sorted(glob.glob(os.path.join(root, tactic, "*.evtx")))
        if files:
            out.append((f"evtx:{tactic}", None, "evtx", files, f"tactic {tactic} ({len(files)} files)"))
    return out


def replay_all(engine, ch, rate: float = MAX_RATE, only: str = None) -> list:
    """Replays every planned dataset not yet replayed (a done run for that dataset_id), in order."""
    results = []
    for ds, tech, fmt, files, name in plan():
        if only and not ds.startswith(only):
            continue
        with engine.connect() as conn:
            done = conn.execute(text("SELECT 1 FROM attack_runs WHERE dataset_id=:d AND status='done'"), {"d": ds}).first()
        if done:
            continue
        r = replay(engine, ch, ds, tech, files, rate, fmt=fmt, test_name=name)
        results.append(r)
        print(json.dumps(r, default=str), flush=True)
        if r["aborted"]:
            break
    return results


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dataset", help="dataset id, e.g. splunk:T1136.001/atomic_red_team")
    p.add_argument("--technique")
    p.add_argument("--format", choices=sorted(READERS), default="splunk")
    p.add_argument("--rate", type=float, default=MAX_RATE)
    p.add_argument("--all", action="store_true", help="replay every planned dataset not yet replayed")
    p.add_argument("--only", help="with --all: dataset id prefix (splunk:, otrf:, evtx:)")
    p.add_argument("--plan", action="store_true", help="print the plan and exit")
    p.add_argument("files", nargs="*")
    a = p.parse_args(argv)
    if a.plan:
        for ds, tech, fmt, files, _ in plan():
            print(ds, tech, fmt, len(files))
        return 0
    if a.all:
        replay_all(db.engine(), db.clickhouse(), a.rate, a.only)
        return 0
    if not (a.dataset and a.files):
        p.error("--dataset and files are required (or --all)")
    print(json.dumps(replay(db.engine(), db.clickhouse(), a.dataset, a.technique, a.files, a.rate, fmt=a.format), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
