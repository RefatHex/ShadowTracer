# Phase 7.0 ML image (docs/ML_FOUNDATION.md): the MLflow server, the enrichment worker and the
# normal-activity schedule share it. The docker CLI is only used by the normal-activity
# schedule (docker exec into the lab agent; lab transport, like ti-sync - backlog S10).
FROM docker:27-cli AS dockercli
FROM python:3.12-slim
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY shadowtracer/ml/requirements.txt .
# Phase 7.5: CPU-only torch first (the default wheel drags in ~2 GB of CUDA libs we never use on
# this CPU lab), then the rest. Then bake the all-MiniLM-L6-v2 model into the image so the enricher
# never downloads it at runtime (offline-friendly; model cached under /opt/models).
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.5.1 \
 && pip install --no-cache-dir -r requirements.txt
ENV SENTENCE_TRANSFORMERS_HOME=/opt/models HF_HOME=/opt/models
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
COPY shadowtracer/ml/shadowtracer_ml ./shadowtracer_ml
# ml-scorer (7.1) reuses ingest's alert normaliser, topic helpers and Kafka security config.
COPY shadowtracer/ingest/shadowtracer_ingest /ingest/shadowtracer_ingest
ENV MLFLOW_DISABLE_AGENT_HINT=1 PYTHONUNBUFFERED=1
