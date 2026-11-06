"""phase 7.0: ML foundation - activity runs, replay agents, labels, verdict reviews, scores

Revision ID: d8a2e6f1c3b7
Revises: c4f1a9e7d2b5
Create Date: 2026-11-06

docs/ML_FOUNDATION.md.
- attack_runs / attack_run_steps: every recorded activity window (Atomic Red Team or
  Caldera run by the owner, scheduled normal activity, dataset replays): tool, source,
  technique, agent, start/end. Caldera operations import their steps.
- replay_agents: dedicated agent ids that only ever carry replayed dataset events.
- ml_labels: one row per labelled incident and label origin, with confidence.
- ml_verdict_reviews: an analyst triage verdict is training data only after a review.
- incidents.ml_*: the enrichment worker's score and reasons (never an action).
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'd8a2e6f1c3b7'
down_revision: Union[str, Sequence[str], None] = 'c4f1a9e7d2b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE attack_runs (
      run_id       text PRIMARY KEY,
      tenant_key   varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      tool         text NOT NULL CHECK (tool IN ('atomic', 'caldera', 'normal', 'replay')),
      source       text NOT NULL,                 -- atomic_linux | caldera | normal_activity | replay:<dataset>
      label        text NOT NULL CHECK (label IN ('attack', 'benign')),
      technique    text,                          -- ATT&CK id (attack) or look-alike id (benign)
      test_name    text,
      agent        text,                          -- agent name, or NULL for replays (see replay_agents)
      dataset_id   text,
      started_at   timestamptz NOT NULL,
      ended_at     timestamptz,
      status       text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'aborted')),
      recorded_by  text NOT NULL,
      details      jsonb NOT NULL DEFAULT '{}'
    );
    CREATE INDEX attack_runs_window ON attack_runs (tenant_key, agent, started_at);
    CREATE TABLE attack_run_steps (
      id          bigserial PRIMARY KEY,
      run_id      text NOT NULL REFERENCES attack_runs(run_id),
      step_no     integer NOT NULL,
      technique   text,
      name        text,
      agent       text,
      started_at  timestamptz,
      ended_at    timestamptz,
      status      text,
      details     jsonb NOT NULL DEFAULT '{}',
      UNIQUE (run_id, step_no)
    );
    CREATE TABLE replay_agents (
      agent_id    text NOT NULL,
      agent_name  text NOT NULL,
      tenant_key  varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      dataset_id  text NOT NULL,
      created_at  timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_key, agent_id)
    );
    CREATE TABLE ml_labels (
      id          bigserial PRIMARY KEY,
      incident_id integer NOT NULL REFERENCES incidents(id),
      tenant_key  varchar(64) NOT NULL,
      label       text NOT NULL CHECK (label IN ('attack', 'benign')),
      technique   text,
      source      text NOT NULL,                  -- atomic_linux | caldera | normal_activity | replay:<ds> | analyst | ti_fp
      run_id      text REFERENCES attack_runs(run_id),
      dataset_id  text,
      origin      text NOT NULL CHECK (origin IN ('attack_window', 'normal_window', 'dataset_label',
                                                  'analyst_verdict', 'ti_false_positive')),
      confidence  real NOT NULL CHECK (confidence BETWEEN 0 AND 1),
      labeled_at  timestamptz NOT NULL DEFAULT now(),
      details     jsonb NOT NULL DEFAULT '{}',
      UNIQUE (incident_id, origin)
    );
    CREATE INDEX ml_labels_source ON ml_labels (source, label);
    CREATE TABLE ml_verdict_reviews (
      id              bigserial PRIMARY KEY,
      incident_id     integer NOT NULL REFERENCES incidents(id),
      tenant_key      varchar(64) NOT NULL,
      verdict         text NOT NULL,              -- escalate | false_positive (from the audited triage)
      analyst         text NOT NULL,              -- audit actor (user id)
      analyst_role    text NOT NULL,
      audit_id        bigint,
      reviewed_by     text,
      reviewed_at     timestamptz,
      approved        boolean,
      UNIQUE (incident_id, analyst, verdict)
    );
    ALTER TABLE incidents ADD COLUMN ml_score real, ADD COLUMN ml_reasons jsonb, ADD COLUMN ml_model text,
                          ADD COLUMN ml_scored_at timestamptz;
    CREATE INDEX incidents_ml_unscored ON incidents (closed_at) WHERE state = 'closed' AND ml_scored_at IS NULL;
    """))
    for t in ("attack_runs", "attack_run_steps", "replay_agents", "ml_labels", "ml_verdict_reviews"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {APP_ROLE}"))
    for s in ("attack_run_steps_id_seq", "ml_labels_id_seq", "ml_verdict_reviews_id_seq"):
        conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE {s} TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text(
        "DROP TABLE ml_verdict_reviews, ml_labels, replay_agents, attack_run_steps, attack_runs; "
        "DROP INDEX IF EXISTS incidents_ml_unscored; "
        "ALTER TABLE incidents DROP COLUMN ml_score, DROP COLUMN ml_reasons, DROP COLUMN ml_model, DROP COLUMN ml_scored_at"))
