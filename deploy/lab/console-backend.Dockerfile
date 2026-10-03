# ShadowTracer console backend (FastAPI). Built from the repo root:
#   docker build -f deploy/lab/console-backend.Dockerfile -t shadowtracer-lab/console-backend:local .
FROM python:3.12-slim

WORKDIR /app
COPY shadowtracer/console/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shadowtracer/console/backend/app ./app
COPY shadowtracer/console/backend/cli.py .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
