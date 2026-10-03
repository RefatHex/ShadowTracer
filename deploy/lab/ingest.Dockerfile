# Shared image for the shipper and writer (Phase 4 follow-up 2) - same
# package, different entrypoint script picked by the compose service's
# `command:`. Built from the repo root:
#   docker build -f deploy/lab/ingest.Dockerfile -t shadowtracer-lab/ingest:local .

FROM python:3.12-slim
WORKDIR /app
COPY shadowtracer/ingest/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shadowtracer/ingest/shadowtracer_ingest ./shadowtracer_ingest
COPY shadowtracer/ingest/run_shipper.py shadowtracer/ingest/run_writer.py ./

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD python3 -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"METRICS_PORT\",\"9101\")}/', timeout=3)"
