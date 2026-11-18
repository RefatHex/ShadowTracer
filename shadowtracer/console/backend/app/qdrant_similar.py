"""Phase 7.5: the console's read-only view of the similar-incidents vector store. The ml-enricher
owns writing vectors (sentence-transformers + Qdrant); the console only QUERIES by an incident's
already-stored vector, so it needs qdrant-client but neither torch nor the model. Every query is
tenant-filtered here, so one tenant can never retrieve another's incidents (verified by test)."""
import os
import uuid

COLLECTION = "incidents"


def point_id(tenant_key: str, incident_id: int) -> str:
    # must match shadowtracer_ml.similar.point_id exactly
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_key}/{incident_id}"))


_client = None


def _get_client():
    global _client
    if _client is None:
        from qdrant_client import QdrantClient
        _client = QdrantClient(url=os.environ.get("QDRANT_URL", "http://qdrant:6333"), timeout=5)
    return _client


def similar(tenant_key: str, incident_id: int, k: int = 5) -> list:
    """Top-k incidents similar to this one, ALWAYS scoped to tenant_key. Returns [] if the incident
    isn't indexed yet or Qdrant is unreachable (best-effort; never raises to the request)."""
    from qdrant_client import models as qm
    try:
        hits = _get_client().recommend(
            COLLECTION, positive=[point_id(tenant_key, incident_id)], limit=k + 1,
            query_filter=qm.Filter(must=[qm.FieldCondition(key="tenant_key", match=qm.MatchValue(value=tenant_key))]),
            with_payload=True)
    except Exception:  # noqa: BLE001 - not indexed yet, or Qdrant down: show an empty section, never 500
        return []
    out = []
    for h in hits:
        if h.payload.get("incident_id") == incident_id:
            continue
        out.append({"incident_id": int(h.payload["incident_id"]), "score": round(float(h.score), 4)})
    return out[:k]
