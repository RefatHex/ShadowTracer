# Shared image for the correlator and closer (Phase 5A Step 1) - same
# package, different entrypoint script picked by each compose service's
# command. Needs shadowtracer/ingest's normalizer.py (imported directly,
# not duplicated - see shadowtracer_correlate/consumer.py), so that
# directory is copied in too. Built from the repo root:
#   docker build -f deploy/lab/correlate.Dockerfile -t shadowtracer-lab/correlate:local .

FROM python:3.12-slim
WORKDIR /app
COPY shadowtracer/correlate/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shadowtracer/correlate/shadowtracer_correlate ./shadowtracer_correlate
COPY shadowtracer/correlate/run_correlator.py shadowtracer/correlate/run_closer.py ./
COPY shadowtracer/ingest/shadowtracer_ingest /ingest/shadowtracer_ingest

# Unlike ingest.Dockerfile's shipper/writer split, both commands this
# image runs always get an explicit METRICS_PORT from docker-compose.yml
# (9104 correlator, 9105 closer) - no risk of the "writer's default
# differs from the shipper's" mismatch that bit run_writer.py once.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD python3 -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"METRICS_PORT\"]}/', timeout=3)"
