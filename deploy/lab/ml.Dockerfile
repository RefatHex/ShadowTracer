# Phase 7.0 ML image (docs/ML_FOUNDATION.md): the MLflow server, the enrichment worker and the
# normal-activity schedule share it. The docker CLI is only used by the normal-activity
# schedule (docker exec into the lab agent; lab transport, like ti-sync - backlog S10).
FROM docker:27-cli AS dockercli
FROM python:3.12-slim
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY shadowtracer/ml/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shadowtracer/ml/shadowtracer_ml ./shadowtracer_ml
ENV MLFLOW_DISABLE_AGENT_HINT=1 PYTHONUNBUFFERED=1
