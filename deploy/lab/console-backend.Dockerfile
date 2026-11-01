# ShadowTracer console backend (FastAPI). Built from the repo root:
#   docker build -f deploy/lab/console-backend.Dockerfile -t shadowtracer-lab/console-backend:local .
FROM python:3.12-slim

WORKDIR /app
COPY shadowtracer/console/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shadowtracer/console/backend/app ./app
COPY shadowtracer/console/backend/cli.py .
# Phase 5.6 Item 4: app/version.py resolves this 3 levels up from its own
# location (../../../VERSION) - matches the dev checkout's real depth
# (app -> backend -> console -> shadowtracer/VERSION); here that's
# /app/app -> /app -> / -> /VERSION.
COPY shadowtracer/VERSION /VERSION

# Phase 5B Step 2: the ATT&CK coverage map router imports
# shadowtracer_ingest.ruleset the same way shadowtracer_correlate already
# does (sys.path insert at a relative depth that resolves to /ingest in
# both the dev checkout and here - see attack_coverage.py), and needs the
# real, bundled ruleset + MITRE ATT&CK data it parses at request time.
COPY shadowtracer/ingest/shadowtracer_ingest /ingest/shadowtracer_ingest
COPY ruleset/rules ./ruleset/rules
COPY ruleset/mitre/enterprise-attack.json ./ruleset/mitre/enterprise-attack.json

EXPOSE 8000
# Phase 5.6 Item 9: /health/ready (real Postgres/ClickHouse checks, not
# just liveness) over /health - same stdlib urllib pattern
# ingest.Dockerfile already uses, no new dependency. Returns 503 on a
# real dependency failure, which urlopen raises on - a non-zero exit,
# same as every other healthcheck in this compose file.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
