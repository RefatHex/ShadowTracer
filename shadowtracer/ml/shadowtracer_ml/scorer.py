"""ml-scorer (Phase 7.1): a side consumer that scores every alert for anomaly with a per-tenant
HalfSpaceTrees model, live. Its own Kafka consumer group on ALERTS_TOPIC_PATTERN - never the hot
path (read-only on alerts, writes only its own ClickHouse table). Scores are advisory; nothing
acts on them.

For each alert: normalize -> per-tenant AnomalyModel.observe (score then learn) -> a row in
ClickHouse ml_scores (ReplacingMergeTree on alert identity + model version, so replaying the
group after a restart overwrites, never duplicates). Offsets are committed only after the batch
is written. Each tenant's model is checkpointed to a volume and restored on restart; an
incompatible checkpoint (feature/algorithm/River-version change) is discarded and the model warms
up again. The model is registered once per start in MLflow.

  python -m shadowtracer_ml.scorer
"""
import json
import logging
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ingest"))      # lab venv
sys.path.insert(0, "/ingest")                                                            # container image
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env  # noqa: E402
from shadowtracer_ingest.normalizer import normalize_alert  # noqa: E402
from shadowtracer_ingest.topics import ALERTS_TOPIC_PATTERN, tenant_from_alerts_topic  # noqa: E402

from . import db, hst  # noqa: E402

log = logging.getLogger("ml-scorer")
GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "shadowtracer-ml-scorer")
STATE_DIR = os.environ.get("ML_SCORER_STATE_DIR", "/state")
FLUSH_ROWS = 500
FLUSH_SECONDS = 2.0
CHECKPOINT_SECONDS = float(os.environ.get("ML_SCORER_CHECKPOINT_SECONDS", "300"))
REGISTERED_MODEL = "incident-anomaly-hst"


class Models:
    """Per-tenant AnomalyModel, restored from / checkpointed to STATE_DIR (one file per tenant)."""
    def __init__(self, state_dir: str = STATE_DIR):
        self.state_dir, self.models, self.dirty = state_dir, {}, set()
        os.makedirs(state_dir, exist_ok=True)

    def _path(self, tenant: str) -> str:
        return os.path.join(self.state_dir, f"{tenant}.{hst.MODEL_VERSION}.ckpt")

    def get(self, tenant: str) -> hst.AnomalyModel:
        m = self.models.get(tenant)
        if m is None:
            m = self._restore(tenant) or hst.AnomalyModel()
            self.models[tenant] = m
        return m

    def _restore(self, tenant: str):
        path = self._path(tenant)
        if not os.path.exists(path):
            return None
        try:
            m = hst.AnomalyModel.load_bytes(open(path, "rb").read())
            log.info("restored %s model (n_seen=%d)", tenant, m.n_seen)
            return m
        except hst.CheckpointIncompatible as exc:
            log.warning("discarding %s checkpoint, warming up again: %s", tenant, exc)
            return None

    def checkpoint(self) -> int:
        n = 0
        for tenant in list(self.dirty):
            path = self._path(tenant)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(self.models[tenant].save_bytes())
            os.replace(tmp, path)
            n += 1
        self.dirty.clear()
        return n


def score_row(event, tenant: str, score, reasons: list) -> list:
    import datetime as dt
    return [tenant, event.cluster_node or "", event.alert_id, hst.MODEL_VERSION,
            float(score) if score is not None else 0.0, 1 if score is not None else 0,
            json.dumps(reasons), dt.datetime.now(dt.timezone.utc)]


def flush(ch, rows: list) -> None:
    if rows:
        ch.insert("ml_scores", rows, column_names=["tenant_id", "cluster_node", "alert_id", "model_version",
                                                   "score", "warm", "reasons", "computed_at"])
        rows.clear()


def register_model() -> None:
    try:
        import mlflow
        mlflow.set_experiment("incident-anomaly")
        c = mlflow.MlflowClient()
        try:
            c.create_registered_model(REGISTERED_MODEL)
        except Exception:  # noqa: BLE001 - already exists
            pass
        with mlflow.start_run(run_name=f"{hst.MODEL_VERSION}-start"):
            mlflow.log_params({"model_version": hst.MODEL_VERSION, "n_trees": hst.N_TREES, "height": hst.HEIGHT,
                               "window": hst.WINDOW, "warmup": hst.WARMUP, "feature_version": hst.af.ALERT_FEATURE_VERSION,
                               "seed": hst.SEED})
            mlflow.set_tag("model_version", hst.MODEL_VERSION)
            mlflow.log_text(
                f"# Model card: {REGISTERED_MODEL}\n\n**Purpose.** Live per-alert anomaly score (River "
                f"HalfSpaceTrees), one model per tenant, warmed online. Advisory only - never triggers actions.\n\n"
                f"**Features.** alert_features {hst.af.ALERT_FEATURE_VERSION} (no source-revealing fields).\n\n"
                f"**Reasons.** Top features by deviation from the running mean - an approximation, not an exact "
                f"HST attribution.\n\n**Limits.** Per-tenant cold start ({hst.WARMUP} alerts warm-up); unsupervised, "
                f"so it flags the unusual, not necessarily the malicious.\n", "model_card.md")
    except Exception:  # noqa: BLE001 - MLflow is not on the scoring path; registration is best-effort
        log.exception("MLflow registration failed (continuing)")


def run(stop_flag=None):
    from confluent_kafka import Consumer
    stop_flag = stop_flag or threading.Event()
    ch = db.clickhouse()
    models = Models()
    conf = {"bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094"),
            "group.id": GROUP_ID, "enable.auto.commit": False, "auto.offset.reset": "latest",
            "topic.metadata.refresh.interval.ms": 10000, **kafka_client_config_from_env()}
    consumer = Consumer(conf)
    consumer.subscribe([ALERTS_TOPIC_PATTERN])
    register_model()
    rows, last_flush, last_ckpt = [], time.monotonic(), time.monotonic()
    skipped = [0]          # malformed alerts the writer dead-letters anyway; counted, not spewed
    log.info("ml-scorer up: group=%s model=%s", GROUP_ID, hst.MODEL_VERSION)
    try:
        while not stop_flag.is_set():
            msg = consumer.poll(1.0)
            now = time.monotonic()
            if msg is not None and not msg.error():
                tenant = tenant_from_alerts_topic(msg.topic())
                if tenant:
                    try:
                        event = normalize_alert(msg.value().decode("utf-8", errors="replace"), tenant)
                        score, reasons, _ = models.get(tenant).observe(event)
                        models.dirty.add(tenant)
                        rows.append(score_row(event, tenant, score, reasons))
                    except Exception:  # noqa: BLE001 - one unparseable alert never stops the stream
                        skipped[0] += 1
                        # malformed alerts (bad/absent timestamp etc.) are expected and dead-lettered
                        # upstream; log the first with a trace, then just count (no per-alert spew).
                        (log.exception if skipped[0] == 1 else log.debug)("skipping an unparseable %s alert", tenant)
            if rows and (len(rows) >= FLUSH_ROWS or now - last_flush >= FLUSH_SECONDS):
                flush(ch, rows)
                consumer.commit(asynchronous=False)     # at-least-once; ReplacingMergeTree dedups on replay
                last_flush = now
            if now - last_ckpt >= CHECKPOINT_SECONDS:
                saved = models.checkpoint()
                if saved or skipped[0]:
                    log.info("checkpointed %d models; skipped %d unparseable alerts since start", saved, skipped[0])
                last_ckpt = now
    finally:
        flush(ch, rows)
        try:
            consumer.commit(asynchronous=False)
        except Exception:  # noqa: BLE001
            pass
        models.checkpoint()
        consumer.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    stop = threading.Event()
    import signal
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    run(stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
