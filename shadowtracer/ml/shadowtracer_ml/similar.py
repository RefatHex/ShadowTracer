"""Phase 7.5: similar-incident retrieval. At incident close the enricher builds a short text from the
incident's STRUCTURED fields only (never raw full_log, usernames, IPs or hostnames - similarity is
about attack SHAPE; campaigns already link same attackers), embeds it with a small CPU model
(all-MiniLM-L6-v2, loaded once), and upserts the vector to Qdrant with a tenant-scoped payload. Every
query goes through QdrantIndex, which ALWAYS adds the tenant filter, so one tenant can never retrieve
another's incidents.

Versioned: TEXT_VERSION (the text builder) and EMBED_MODEL (the model) are stored on every vector and
on incidents.ml_sim_text_version; a change re-indexes. Off the hot path - only closed incidents.
"""
import datetime as dt
import ipaddress
import logging
import os
import uuid

log = logging.getLogger("ml-similar")

EMBED_MODEL = "all-MiniLM-L6-v2"     # Apache-2.0
VECTOR_DIM = 384
TEXT_VERSION = "sim-text-v1"
COLLECTION = "incidents"
# the version string stamped on incidents + vectors; bump either part to force a re-index
INDEX_VERSION = f"{TEXT_VERSION}|{EMBED_MODEL}"


# ---- deterministic point id (so re-index overwrites, and delete is exact) -----------------------
def point_id(tenant_key: str, incident_id: int) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_key}/{incident_id}"))


# ---- structured facts (shared by backfill and live) ---------------------------------------------
def _bucket(n: int, edges=(1, 3, 10, 30, 100, 300, 1000)) -> str:
    for e in edges:
        if n <= e:
            return f"<={e}"
    return f">{edges[-1]}"


def _duration_bucket(first, last) -> str:
    secs = max(0.0, (last - first).total_seconds()) if first and last else 0.0
    for e, label in ((60, "<1m"), (300, "<5m"), (1800, "<30m"), (3600, "<1h"), (21600, "<6h"), (86400, "<1d")):
        if secs <= e:
            return label
    return ">1d"


def _actor_class(source_ips, internal_ranges) -> str:
    nets = []
    for r in internal_ranges:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            pass
    saw = False
    for ip in source_ips or []:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        saw = True
        if not any(addr in n for n in nets) and not addr.is_private:
            return "external"
    return "internal" if saw else "none"


def _file_classes(paths) -> list:
    out = set()
    for p in paths or []:
        p = (p or "").lower()
        if not p:
            continue
        if p.startswith(("/var/www", "/srv/www")):
            out.add("web-root")
        elif p.startswith(("/tmp", "/var/tmp", "/dev/shm")):
            out.add("temp")
        elif "cron" in p or "systemd" in p or p.startswith("/etc/init"):
            out.add("persistence")
        elif p.startswith(("/root", "/home")):
            out.add("home")
        elif p.startswith(("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/etc")):
            out.add("system")
        else:
            out.add("other")
    return sorted(out)


def incident_facts(conn, ch, inc: dict, internal_ranges: list) -> dict:
    """Structured attack-shape facts for one incident. inc is the incidents row (dict). Pulls the
    alert-derived facts (rule descriptions, MITRE tactics, YARA rule names, FIM path classes) from
    ClickHouse, the TI sources from incident_ti, and the analyst verdict from the incident."""
    from sqlalchemy import text
    rule_descs, tactics, yara, paths = set(), set(), set(), set()
    # A sample of alerts captures the DISTINCT shape (rule descriptions, tactics, YARA, path classes);
    # a huge incident's full id list overflows ClickHouse's HTTP form field, and the distinct facts
    # stabilise well before then. ORDER BY makes the sample deterministic (shared by backfill + live).
    rows = conn.execute(text("SELECT node, alert_id FROM incident_alerts WHERE incident_id = :i "
                             "ORDER BY alert_time, id LIMIT 400"), {"i": inc["id"]}).all()
    if rows:
        for rd, mt, yr, fp in ch.query(
            "SELECT arrayDistinct(groupArray(rule_description)) rd, arrayDistinct(arrayFlatten(groupArray(mitre_tactics))) mt, "
            "arrayDistinct(groupArray(extra_fields['yara_rule'])) yr, arrayDistinct(groupArray(extra_fields['syscheck.path'])) fp "
            "FROM events WHERE tenant_id = {t:String} AND (cluster_node, alert_id) IN {ids:Array(Tuple(String,String))}",
            parameters={"t": inc["tenant_key"], "ids": [(r[0], r[1]) for r in rows]}).result_rows:
            rule_descs |= {x for x in rd if x}
            tactics |= {x for x in mt if x}
            yara |= {x for x in yr if x}
            paths |= {x for x in fp if x}
    ti_sources = {s for r in conn.execute(text(
        "SELECT sources FROM incident_ti WHERE incident_id = :i AND tenant_key = :t"),
        {"i": inc["id"], "t": inc["tenant_key"]}) for s in (r[0] or [])}
    return {
        "rule_descriptions": sorted(rule_descs)[:20],
        "rule_groups": sorted(inc.get("rule_groups") or []),
        "mitre_techniques": sorted(inc.get("mitre_ids") or []),
        "mitre_tactics": sorted(tactics),
        "actor_class": _actor_class(inc.get("source_ips"), internal_ranges),
        "target_class": inc.get("os_family") or "unknown",
        "target_role": inc.get("role_tag") or "",
        "alert_count_bucket": _bucket(int(inc.get("alert_count") or 0)),
        "duration_bucket": _duration_bucket(inc.get("first_seen"), inc.get("last_seen")),
        "ti_sources": sorted(ti_sources),
        "yara_rules": sorted(yara),
        "file_classes": _file_classes(paths),
        "verdict": inc.get("triage_status") or "untriaged",
    }


def build_text(f: dict) -> str:
    """Versioned (TEXT_VERSION) deterministic text from the structured facts. Shape only - no raw
    log, usernames, IPs or hostnames ever reach here."""
    seg = [
        "rules: " + "; ".join(f["rule_descriptions"]),
        "groups: " + ", ".join(f["rule_groups"]),
        "mitre techniques: " + ", ".join(f["mitre_techniques"]),
        "mitre tactics: " + ", ".join(f["mitre_tactics"]),
        "actor: " + f["actor_class"],
        "target: " + f["target_class"] + ((" " + f["target_role"]) if f["target_role"] else ""),
        "alerts: " + f["alert_count_bucket"],
        "duration: " + f["duration_bucket"],
        "threat intel: " + ", ".join(f["ti_sources"]),
        "yara: " + ", ".join(f["yara_rules"]),
        "files: " + ", ".join(f["file_classes"]),
        "verdict: " + f["verdict"],
    ]
    return " | ".join(s for s in seg)


# ---- embedding (model loaded once) --------------------------------------------------------------
class Embedder:
    def __init__(self, model_name: str = EMBED_MODEL):
        from sentence_transformers import SentenceTransformer
        self.model_name = model_name
        self._model = SentenceTransformer(model_name)   # cached under SENTENCE_TRANSFORMERS_HOME

    def embed(self, texts: list) -> list:
        return [v.tolist() for v in self._model.encode(texts, batch_size=64, normalize_embeddings=True,
                                                        show_progress_bar=False)]


# ---- Qdrant wrapper: every query is tenant-filtered ---------------------------------------------
class QdrantIndex:
    def __init__(self, url: str = None):
        from qdrant_client import QdrantClient
        self.client = QdrantClient(url=url or os.environ.get("QDRANT_URL", "http://qdrant:6333"))
        self.ensure_collection()

    def ensure_collection(self):
        from qdrant_client import models as qm
        if not self.client.collection_exists(COLLECTION):
            self.client.create_collection(
                COLLECTION, vectors_config=qm.VectorParams(size=VECTOR_DIM, distance=qm.Distance.COSINE))
        # a payload index on tenant_key so the mandatory tenant filter is cheap
        try:
            self.client.create_payload_index(COLLECTION, "tenant_key", field_schema="keyword")
        except Exception:  # noqa: BLE001 - already exists
            pass

    def upsert(self, points: list) -> None:
        """points: list of (tenant_key, incident_id, vector, payload)."""
        from qdrant_client import models as qm
        if not points:
            return
        self.client.upsert(COLLECTION, points=[
            qm.PointStruct(id=point_id(t, i), vector=v, payload={**p, "tenant_key": t, "incident_id": i})
            for (t, i, v, p) in points])

    def _tenant_filter(self, tenant_key: str):
        from qdrant_client import models as qm
        return qm.Filter(must=[qm.FieldCondition(key="tenant_key", match=qm.MatchValue(value=tenant_key))])

    def similar(self, tenant_key: str, incident_id: int, k: int = 5) -> list:
        """Top-k incidents similar to this one, ALWAYS within tenant_key. Uses the incident's own
        stored vector (recommend by point id); returns [] if it isn't indexed yet."""
        from qdrant_client import models as qm
        pid = point_id(tenant_key, incident_id)
        hits = self.client.recommend(
            COLLECTION, positive=[pid], limit=k, query_filter=self._tenant_filter(tenant_key),
            with_payload=True)
        out = []
        for h in hits:
            if h.payload.get("incident_id") == incident_id:
                continue
            out.append({"incident_id": h.payload["incident_id"], "score": round(float(h.score), 4),
                        "verdict": h.payload.get("verdict"), "fingerprint": h.payload.get("fingerprint"),
                        "closed_at": h.payload.get("closed_at")})
        return out[:k]

    def search_vector(self, tenant_key: str, vector: list, k: int = 5) -> list:
        """Top-k by a raw query vector, tenant-filtered (used by the evaluation harness)."""
        hits = self.client.query_points(COLLECTION, query=vector, limit=k,
                                        query_filter=self._tenant_filter(tenant_key), with_payload=True).points
        return [{"incident_id": h.payload["incident_id"], "score": round(float(h.score), 4),
                 "verdict": h.payload.get("verdict")} for h in hits]

    def delete_incidents(self, tenant_key: str, incident_ids: list) -> int:
        if not incident_ids:
            return 0
        self.client.delete(COLLECTION, points_selector=[point_id(tenant_key, i) for i in incident_ids])
        return len(incident_ids)

    def count(self, tenant_key: str = None) -> int:
        flt = self._tenant_filter(tenant_key) if tenant_key else None
        return self.client.count(COLLECTION, count_filter=flt, exact=True).count


# ---- indexing at close (also the backfill: un-indexed = existing closed incidents) ---------------
SINCE = os.environ.get("ML_SINCE", "2026-11-06T11:25:00Z")   # same 7.0 data start the enricher uses

_SELECT = (
    "SELECT i.id, i.tenant_key, i.fingerprint_key, i.triage_status, i.closed_at, i.first_seen, "
    "i.last_seen, i.alert_count, i.rule_groups, i.mitre_ids, i.source_ips, r.os_family, r.role_tag "
    "FROM incidents i LEFT JOIN agent_role_tags r ON r.tenant_key=i.tenant_key AND r.agent_id=i.agent_id "
    "WHERE i.state='closed' AND i.tenant_key = ANY(:t) AND i.closed_at >= CAST(:since AS timestamptz) "
    "AND (i.ml_sim_indexed_at IS NULL OR i.ml_sim_text_version IS DISTINCT FROM :ver) "
    "ORDER BY i.closed_at LIMIT :n FOR UPDATE OF i SKIP LOCKED")


def embed_batch(engine, ch, embedder, index, tenant_list: list, internal_ranges: list, limit: int = 200) -> dict:
    """Index up to `limit` closed incidents that are new or whose text/model version changed. This is
    both the live path (newly closed) and the bounded backfill (existing closed incidents are simply
    un-indexed). Returns stats including total embed seconds."""
    import time
    from sqlalchemy import text
    with engine.begin() as conn:
        incs = [dict(r._mapping) for r in conn.execute(text(_SELECT),
                {"t": tenant_list, "since": SINCE, "ver": INDEX_VERSION, "n": limit})]
        if not incs:
            return {"indexed": 0, "embed_seconds": 0.0}
        facts = [incident_facts(conn, ch, i, internal_ranges) for i in incs]
        texts = [build_text(f) for f in facts]
        t0 = time.monotonic()
        vectors = embedder.embed(texts)
        embed_seconds = time.monotonic() - t0
        points = []
        for i, f, v in zip(incs, facts, vectors):
            payload = {"fingerprint": i.get("fingerprint_key"), "verdict": f["verdict"],
                       "closed_at": i["closed_at"].isoformat() if i.get("closed_at") else None,
                       "text_version": TEXT_VERSION, "model": embedder.model_name}
            points.append((i["tenant_key"], i["id"], v, payload))
        index.upsert(points)
        conn.execute(text("UPDATE incidents SET ml_sim_indexed_at=now(), ml_sim_text_version=:ver "
                          "WHERE id = ANY(:ids)"),
                     {"ver": INDEX_VERSION, "ids": [i["id"] for i in incs]})
    return {"indexed": len(incs), "embed_seconds": round(embed_seconds, 3),
            "ms_per_incident": round(1000 * embed_seconds / len(incs), 1), "first_id": incs[0]["id"]}


def purge_consistency(engine, index, tenant_list: list) -> dict:
    """Delete vectors whose incident no longer exists in Postgres (e.g. purged by the cleanup script).
    Bounded scan per tenant."""
    from sqlalchemy import text
    deleted = 0
    for tenant in tenant_list:
        with engine.connect() as conn:
            live = {r[0] for r in conn.execute(text("SELECT id FROM incidents WHERE tenant_key=:t"), {"t": tenant})}
        # scroll the tenant's vectors
        from qdrant_client import models as qm
        flt = qm.Filter(must=[qm.FieldCondition(key="tenant_key", match=qm.MatchValue(value=tenant))])
        offset, stale = None, []
        while True:
            pts, offset = index.client.scroll(COLLECTION, scroll_filter=flt, with_payload=True,
                                              limit=1000, offset=offset)
            stale += [p.payload["incident_id"] for p in pts if p.payload["incident_id"] not in live]
            if offset is None:
                break
        deleted += index.delete_incidents(tenant, stale)
    return {"deleted": deleted}


def _mlflow_log(stats: dict):
    try:
        import mlflow
        mlflow.set_experiment("similar-incidents")
        with mlflow.start_run(run_name=f"{INDEX_VERSION}"):
            mlflow.log_params({"text_version": TEXT_VERSION, "embed_model": EMBED_MODEL, "vector_dim": VECTOR_DIM})
            mlflow.log_metrics({k: v for k, v in stats.items() if isinstance(v, (int, float))})
    except Exception:  # noqa: BLE001 - MLflow is advisory, never block indexing
        log.debug("mlflow log skipped", exc_info=True)
