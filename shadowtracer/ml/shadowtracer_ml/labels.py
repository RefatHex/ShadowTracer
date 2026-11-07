"""Incident labels (Phase 7.0, docs/ML_FOUNDATION.md "Label quality"). One ml_labels row per
(incident, origin); TEST tenant only.

  attack_window / normal_window  a recorded run (atomic, caldera / normal activity, status done):
      the incident is on the run's agent, overlaps [started_at, ended_at + GRACE], AND has
      activity from the run - at least one of its alerts falls inside that window with either
      (a) an ATT&CK technique matching the run's (parent technique, or any Caldera step's), or
      (b) a rule that did not fire on that agent in the BASELINE before the run (not background).
      confidence: 0.9 for (a), 0.6 for (b) alone, times the share of its alerts inside the window
      (floored at 0.5 of that). Incidents in the window without such activity stay UNLABELLED.
  dataset_label   a replay run: the dataset's dedicated replay agent only ever carries that
      dataset, so its incidents in the run window take the dataset's ATT&CK label; confidence 0.8
      (recordings include some unrelated host noise).
  analyst_verdict escalate -> attack, false_positive -> benign; only from analyst/admin users,
      read from the audit log (incident_triage:<action>), and only once a reviewer approved the
      ml_verdict_reviews row (`review`). Per-analyst counts: `verdict-counts`.
  ti_false_positive  an incident whose TI match an analyst marked false positive -> benign, 0.7.

  python -m shadowtracer_ml.labels run | coverage | verdict-counts
  python -m shadowtracer_ml.labels review --pending | --approve ID [--reject] --by NAME
"""
import argparse
import datetime as dt
import json
import sys

from sqlalchemy import text

from . import db

GRACE = dt.timedelta(seconds=120)          # alerts reach analysisd -> correlator after the run stops
BASELINE = dt.timedelta(hours=24)
VERDICT_LABEL = {"escalate": "attack", "false_positive": "benign"}
ANALYST_ROLES = ("analyst", "admin")


def parent(technique: str) -> str:
    return (technique or "").split(".")[0].upper()


def activity_confidence(run_techniques: set, window_alerts: list, background_rules: set, total_alerts: int):
    """window_alerts: [(rule_id, [mitre technique ids])] of the incident inside the run window.
    -> confidence in (0, 1], or None when the incident shows no activity from the run."""
    if not window_alerts:
        return None
    parents = {parent(t) for t in run_techniques if t}
    by_technique = any(parent(t) in parents for _, ts in window_alerts for t in ts)
    new_rule = any(r not in background_rules for r, _ in window_alerts)
    if not (by_technique or new_rule):
        return None
    share = len(window_alerts) / max(total_alerts, len(window_alerts))
    return round((0.9 if by_technique else 0.6) * max(share, 0.5), 3)


def _agent_ids(ch, conn, tenant: str, run) -> list:
    if run.tool == "replay":
        return [r[0] for r in conn.execute(text("SELECT agent_id FROM replay_agents WHERE tenant_key=:t AND dataset_id=:d"),
                                           {"t": tenant, "d": run.dataset_id})]
    names = {run.agent} | {s[0] for s in conn.execute(text("SELECT DISTINCT agent FROM attack_run_steps WHERE run_id=:r AND agent IS NOT NULL"),
                                                       {"r": run.run_id})}
    # The ids the name had DURING the run: agent ids are reused after re-registration (lab agents
    # were re-created; replay agents took their old ids), so a wider lookup can reach another host.
    rows = ch.query("SELECT DISTINCT agent_id FROM events WHERE tenant_id = {t:String} AND agent_name IN {n:Array(String)} "
                    "AND time BETWEEN {s:DateTime64(3)} - INTERVAL 1 HOUR AND {e:DateTime64(3)} + INTERVAL 1 HOUR "
                    "AND agent_id != '000'",
                    parameters={"t": tenant, "n": sorted(n for n in names if n), "s": run.started_at,
                                "e": run.ended_at or run.started_at}).result_rows
    return [r[0] for r in rows]


def _alert_rules(ch, tenant: str, alert_ids: list) -> dict:
    out = {}
    for i in range(0, len(alert_ids), 2000):
        for aid, rule, techs in ch.query(
                "SELECT alert_id, rule_id, mitre_ids FROM events WHERE tenant_id = {t:String} AND alert_id IN {a:Array(String)}",
                parameters={"t": tenant, "a": alert_ids[i:i + 2000]}).result_rows:
            out[aid] = (rule, list(techs))
    return out


def label_runs(engine, ch, tenant: str) -> dict:
    stats = {}
    with engine.begin() as conn:
        runs = conn.execute(text(
            "SELECT * FROM attack_runs r WHERE tenant_key=:t AND status='done' AND ended_at IS NOT NULL "
            "AND ended_at > now() - interval '7 days' ORDER BY started_at"), {"t": tenant}).all()
        for run in runs:
            if run.ended_at + GRACE > dt.datetime.now(dt.timezone.utc):
                continue                                    # window still open
            ids = _agent_ids(ch, conn, tenant, run)
            if not ids:
                continue
            w0, w1 = run.started_at, run.ended_at + GRACE
            incs = conn.execute(text(
                "SELECT id, alert_count FROM incidents WHERE tenant_key=:t AND agent_id = ANY(:a) AND state='closed' "
                "AND first_seen <= :w1 AND last_seen >= :w0"), {"t": tenant, "a": ids, "w0": w0, "w1": w1}).all()
            if run.tool == "replay":
                # a replay carries the dataset's own label: "attack" for a recorded-attack dataset
                # (0.8), "benign" for a benign-background corpus like BOTSv3 Windows Sysmon (0.6 -
                # background may contain a little un-excluded attack activity; see backlog D17).
                origin, label = "dataset_label", run.label
                conf = (lambda *_: 0.6) if run.label == "benign" else (lambda *_: 0.8)
            else:
                origin, label = ("normal_window", "benign") if run.tool == "normal" else ("attack_window", "attack")
                techniques = {run.technique} | {s[0] for s in conn.execute(text(
                    "SELECT technique FROM attack_run_steps WHERE run_id=:r"), {"r": run.run_id})}
                base = ch.query("SELECT DISTINCT rule_id FROM events WHERE tenant_id={t:String} AND agent_id IN {a:Array(String)} "
                                "AND time >= {b:DateTime64(3)} AND time < {s:DateTime64(3)}",
                                parameters={"t": tenant, "a": ids, "b": w0 - BASELINE, "s": w0}).result_rows
                background = {r[0] for r in base}

                def conf(inc_id, count, _t=techniques, _b=background):
                    aids = [r[0] for r in conn.execute(text(
                        "SELECT alert_id FROM incident_alerts WHERE incident_id=:i AND alert_time BETWEEN :w0 AND :w1"),
                        {"i": inc_id, "w0": w0, "w1": w1})]
                    rules = _alert_rules(ch, tenant, aids)
                    return activity_confidence(_t, [rules[a] for a in aids if a in rules], _b, count)
            n = 0
            for inc in incs:
                c = conf(inc.id, inc.alert_count)
                if c is None:
                    continue
                n += conn.execute(text(
                    "INSERT INTO ml_labels (incident_id, tenant_key, label, technique, source, run_id, dataset_id, origin, confidence) "
                    "VALUES (:i, :t, :l, :tech, :s, :r, :d, :o, :c) ON CONFLICT (incident_id, origin) DO NOTHING"),
                    {"i": inc.id, "t": tenant, "l": label, "tech": run.technique, "s": run.source, "r": run.run_id,
                     "d": run.dataset_id, "o": origin, "c": c}).rowcount
            stats[run.run_id] = {"incidents_in_window": len(incs), "labelled": n}
    return stats


def collect_verdicts(engine, tenant: str) -> int:
    """Audited triage verdicts from analyst/admin users -> ml_verdict_reviews (pending review)."""
    with engine.begin() as conn:
        return conn.execute(text("""
            INSERT INTO ml_verdict_reviews (incident_id, tenant_key, verdict, analyst, analyst_role, audit_id)
            SELECT CAST(a.target AS integer), t.tenant_key, split_part(a.action, ':', 2), a.actor, u.role, a.id
            FROM audit_log a JOIN tenants t ON t.id = a.tenant_id
            JOIN users u ON u.tenant_id = a.tenant_id AND u.email = a.actor
            JOIN incidents i ON i.id = CAST(a.target AS integer) AND i.tenant_key = t.tenant_key
            WHERE t.tenant_key = :t AND a.outcome = 'success' AND u.role = ANY(:roles)
              AND a.action IN ('incident_triage:escalate', 'incident_triage:false_positive') AND a.target ~ '^[0-9]+$'
            ON CONFLICT (incident_id, analyst, verdict) DO NOTHING"""), {"t": tenant, "roles": list(ANALYST_ROLES)}).rowcount


def label_verdicts(engine, tenant: str) -> int:
    """Only approved reviews become labels; conflicting approved verdicts on one incident -> none."""
    with engine.begin() as conn:
        rows = conn.execute(text(
            "SELECT incident_id, array_agg(DISTINCT verdict) v, array_agg(DISTINCT analyst) a FROM ml_verdict_reviews "
            "WHERE tenant_key=:t AND approved IS TRUE GROUP BY incident_id"), {"t": tenant}).all()
        n = 0
        for r in rows:
            if len(r.v) != 1 or r.v[0] not in VERDICT_LABEL:
                continue
            n += conn.execute(text(
                "INSERT INTO ml_labels (incident_id, tenant_key, label, source, origin, confidence, details) "
                "VALUES (:i, :t, :l, 'analyst', 'analyst_verdict', :c, CAST(:d AS jsonb)) ON CONFLICT (incident_id, origin) DO NOTHING"),
                {"i": r.incident_id, "t": tenant, "l": VERDICT_LABEL[r.v[0]], "c": 0.9 if len(r.a) > 1 else 0.8,
                 "d": json.dumps({"analysts": len(r.a)})}).rowcount
        return n


def label_ti_feedback(engine, tenant: str) -> int:
    with engine.begin() as conn:
        return conn.execute(text("""
            INSERT INTO ml_labels (incident_id, tenant_key, label, source, origin, confidence, details)
            SELECT DISTINCT ON (it.incident_id) it.incident_id, f.tenant_key, 'benign', 'ti_fp', 'ti_false_positive', 0.7,
                   jsonb_build_object('feedback_id', f.id)
            FROM ti_feedback f JOIN incident_ti it ON it.id = f.incident_ti_id
            WHERE f.tenant_key = :t AND f.label = 'false_positive'
            ON CONFLICT (incident_id, origin) DO NOTHING"""), {"t": tenant}).rowcount


def run_all(engine, ch, tenant: str) -> dict:
    return {"runs": label_runs(engine, ch, tenant), "verdicts_collected": collect_verdicts(engine, tenant),
            "analyst_labels": label_verdicts(engine, tenant), "ti_fp_labels": label_ti_feedback(engine, tenant)}


def coverage(engine, ch, tenant: str) -> list:
    """Per source: techniques run/replayed, how many produced alerts / incidents, which rules."""
    out = []
    with engine.connect() as conn:
        runs = conn.execute(text("SELECT * FROM attack_runs WHERE tenant_key=:t AND status='done' ORDER BY source"), {"t": tenant}).all()
        for run in runs:
            ids = _agent_ids(ch, conn, tenant, run)
            w0, w1 = run.started_at, (run.ended_at or run.started_at) + GRACE
            rules = ch.query("SELECT rule_id, count() FROM events WHERE tenant_id={t:String} AND agent_id IN {a:Array(String)} "
                             "AND time BETWEEN {w0:DateTime64(3)} AND {w1:DateTime64(3)} GROUP BY rule_id ORDER BY count() DESC",
                             parameters={"t": tenant, "a": ids or ["-"], "w0": w0, "w1": w1}).result_rows
            labelled = conn.execute(text("SELECT count(*) FROM ml_labels WHERE run_id=:r"), {"r": run.run_id}).scalar()
            out.append({"source": run.source, "technique": run.technique, "run_id": run.run_id, "label": run.label,
                        "alerts": sum(c for _, c in rules), "rules": [r for r, _ in rules[:10]], "labelled_incidents": labelled})
    return out


def coverage_table(rows: list) -> str:
    agg = {}
    for r in rows:
        src = r["source"] if not r["source"].startswith("replay:") else "replay:" + r["source"].split(":")[1]
        a = agg.setdefault(src, {"techniques": set(), "with_alerts": set(), "incidents": 0, "rules": set()})
        key = r["technique"] or r["run_id"]                # EVTX datasets carry a tactic, not a technique
        a["techniques"].add(key)
        if r["alerts"]:
            a["with_alerts"].add(key)
        a["incidents"] += r["labelled_incidents"]
        a["rules"].update(r["rules"])
    lines = ["| source | techniques run/replayed | produced alerts | labelled incidents | rules (count: first 12) |", "|---|---|---|---|---|"]
    for s, a in sorted(agg.items()):
        lines.append(f"| {s} | {len(a['techniques'])} ({', '.join(sorted(t for t in a['techniques'] if t.startswith('T')))}) | "
                     f"{len(a['with_alerts'])} | {a['incidents']} | {len(a['rules'])}: {', '.join(sorted(a['rules'])[:12])} |")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["run", "coverage", "verdict-counts", "review"])
    p.add_argument("--pending", action="store_true")
    p.add_argument("--approve", type=int)
    p.add_argument("--reject", action="store_true")
    p.add_argument("--by")
    a = p.parse_args(argv)
    engine, tenant = db.engine(), db.test_tenant()
    if a.cmd == "run":
        print(json.dumps(run_all(engine, db.clickhouse(), tenant), indent=1, default=str))
    elif a.cmd == "coverage":
        print(coverage_table(coverage(engine, db.clickhouse(), tenant)))
    elif a.cmd == "verdict-counts":
        with engine.connect() as conn:
            for r in conn.execute(text(
                    "SELECT analyst, analyst_role, verdict, count(*) total, count(*) FILTER (WHERE approved) approved, "
                    "count(*) FILTER (WHERE approved IS NULL) pending FROM ml_verdict_reviews WHERE tenant_key=:t "
                    "GROUP BY 1,2,3 ORDER BY 1,3"), {"t": tenant}):
                print(dict(r._mapping))
    elif a.pending or a.approve is None:
        with engine.connect() as conn:
            for r in conn.execute(text("SELECT id, incident_id, verdict, analyst, analyst_role, audit_id FROM ml_verdict_reviews "
                                       "WHERE tenant_key=:t AND approved IS NULL ORDER BY id"), {"t": tenant}):
                print(dict(r._mapping))
    else:
        if not a.by:
            p.error("--by is required to approve or reject")
        with engine.begin() as conn:
            conn.execute(text("UPDATE ml_verdict_reviews SET approved=:ok, reviewed_by=:by, reviewed_at=now() "
                              "WHERE id=:id AND tenant_key=:t AND analyst <> :by"),
                         {"ok": not a.reject, "by": a.by, "id": a.approve, "t": tenant})
    return 0


if __name__ == "__main__":
    sys.exit(main())
