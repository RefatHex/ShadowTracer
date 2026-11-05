# ti-matcher (Phase 6.1c, THREAT_INTEL.md §3.1). Same Python dependencies as the
# correlator (Kafka, Postgres, ClickHouse); imports shadowtracer_ingest's normaliser,
# topic and tenant helpers directly. Built from the repo root.
FROM python:3.12-slim
WORKDIR /app
COPY shadowtracer/correlate/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shadowtracer/ingest/shadowtracer_ingest ./shadowtracer_ingest
COPY shadowtracer/intel/shadowtracer_intel ./shadowtracer_intel
COPY shadowtracer/intel/run_ti_matcher.py ./
CMD ["python3", "run_ti_matcher.py"]
