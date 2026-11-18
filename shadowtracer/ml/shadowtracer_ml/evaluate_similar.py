"""Phase 7.5 evaluation: does embedding retrieval put same-technique incidents in the top-5 better
than a simple baseline? Pool = attack-labelled incidents (ml_labels.technique, from ART + replayed
datasets). For each, retrieve top-5 OTHER incidents from the labelled pool - once by Qdrant vector
similarity, once by rule-group Jaccard (the baseline) - and measure precision@5 = fraction of the 5
that share the technique (and, separately, the tactic prefix). Broken down per OS and per source.
Reported even if embedding loses.

  python -m shadowtracer_ml.evaluate_similar          # prints the table
"""
import json
import os
import sys

from sqlalchemy import text

from . import db, similar

K = 5


def load_pool(engine, tenant: str) -> dict:
    """incident_id -> {technique, tactic, os, source, rule_groups} for attack-labelled incidents."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT l.incident_id, l.technique, l.source, i.rule_groups, COALESCE(r.os_family,'unknown') os "
            "FROM ml_labels l JOIN incidents i ON i.id = l.incident_id "
            "LEFT JOIN agent_role_tags r ON r.tenant_key = i.tenant_key AND r.agent_id = i.agent_id "
            "WHERE l.tenant_key = :t AND l.label = 'attack' AND coalesce(l.technique,'') <> '' "
            "AND i.ml_sim_indexed_at IS NOT NULL"), {"t": tenant}).all()
    pool = {}
    for iid, tech, src, groups, os_ in rows:
        tactic = tech.split(".")[0] if tech else ""
        source = (src or "").split(":")[1] if ":" in (src or "") else (src or "unknown")  # splunk/evtx/otrf/...
        pool[iid] = {"technique": tech, "tactic": tactic, "os": os_ or "unknown",
                     "source": source, "rule_groups": set(groups or [])}
    return pool


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 0.0


def baseline_topk(iid: int, pool: dict, k: int) -> list:
    me = pool[iid]["rule_groups"]
    scored = sorted(((o, _jaccard(me, pool[o]["rule_groups"])) for o in pool if o != iid),
                    key=lambda x: x[1], reverse=True)
    return [o for o, _ in scored[:k]]


def embedding_topk(index, tenant: str, iid: int, pool: dict, k: int) -> list:
    # retrieve a buffer, keep those in the labelled pool, take k
    hits = index.similar(tenant, iid, k=k * 6)
    return [h["incident_id"] for h in hits if h["incident_id"] in pool and h["incident_id"] != iid][:k]


def _precision(topk: list, me: dict, pool: dict, field: str) -> float:
    if not topk:
        return 0.0
    return sum(1 for o in topk if pool[o][field] == me[field]) / len(topk)


def evaluate(engine, index, tenant: str) -> dict:
    pool = load_pool(engine, tenant)
    groups = {}   # (dim, value) -> accumulators
    overall = {"n": 0, "emb_tech": 0.0, "emb_tac": 0.0, "base_tech": 0.0, "base_tac": 0.0}
    per_os, per_src = {}, {}
    for iid, me in pool.items():
        emb = embedding_topk(index, tenant, iid, pool, K)
        base = baseline_topk(iid, pool, K)
        if not emb and not base:
            continue
        row = {"emb_tech": _precision(emb, me, pool, "technique"), "emb_tac": _precision(emb, me, pool, "tactic"),
               "base_tech": _precision(base, me, pool, "technique"), "base_tac": _precision(base, me, pool, "tactic")}
        for agg in (overall, per_os.setdefault(me["os"], {"n": 0, "emb_tech": 0.0, "emb_tac": 0.0, "base_tech": 0.0, "base_tac": 0.0}),
                    per_src.setdefault(me["source"], {"n": 0, "emb_tech": 0.0, "emb_tac": 0.0, "base_tech": 0.0, "base_tac": 0.0})):
            agg["n"] += 1
            for k2 in ("emb_tech", "emb_tac", "base_tech", "base_tac"):
                agg[k2] += row[k2]
    return {"pool": len(pool), "overall": overall, "per_os": per_os, "per_source": per_src}


def _fmt(agg: dict) -> str:
    n = agg["n"] or 1
    return (f"n={agg['n']:>4}  P@5 technique: embed {agg['emb_tech']/n:.3f} vs baseline {agg['base_tech']/n:.3f}"
            f"   | tactic: embed {agg['emb_tac']/n:.3f} vs baseline {agg['base_tac']/n:.3f}")


def main(argv=None) -> int:
    engine = db.engine()
    index = similar.QdrantIndex()
    tenant = (argv or sys.argv[1:] or [db.test_tenant()])[0]
    res = evaluate(engine, index, tenant)
    print(f"\nSimilar-incident retrieval evaluation (tenant {tenant[:8]}…, pool={res['pool']} labelled attack incidents, K={K})")
    print("=" * 100)
    print("OVERALL   ", _fmt(res["overall"]))
    print("\nper OS:")
    for os_, agg in sorted(res["per_os"].items()):
        print(f"  {os_:<10}", _fmt(agg))
    print("\nper source:")
    for src, agg in sorted(res["per_source"].items()):
        print(f"  {src:<14}", _fmt(agg))
    # MLflow
    try:
        import mlflow
        mlflow.set_experiment("similar-incidents")
        n = res["overall"]["n"] or 1
        with mlflow.start_run(run_name=f"eval-{similar.INDEX_VERSION}"):
            mlflow.log_params({"text_version": similar.TEXT_VERSION, "embed_model": similar.EMBED_MODEL, "k": K, "pool": res["pool"]})
            mlflow.log_metrics({"p5_tech_embed": res["overall"]["emb_tech"] / n, "p5_tech_baseline": res["overall"]["base_tech"] / n,
                                "p5_tactic_embed": res["overall"]["emb_tac"] / n, "p5_tactic_baseline": res["overall"]["base_tac"] / n})
    except Exception:  # noqa: BLE001
        pass
    print("\n(logged to MLflow experiment 'similar-incidents')")
    return 0


if __name__ == "__main__":
    sys.exit(main())
