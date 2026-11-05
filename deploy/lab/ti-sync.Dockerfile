# Phase 6.1b: ti-sync (shadowtracer/intel). Pulls threat-intel feeds into the IOC store
# and deploys CDB lists + TI rules to each tenant manager cluster through the safe
# reload wrapper. Lab transport: `docker exec` into the manager containers through the
# host's Docker socket (docker-compose.yml) - lab only; production uses a small agent on
# each manager host (THREAT_INTEL.md §4.4, backlog S10).
FROM docker:27-cli AS dockercli

FROM python:3.12-slim
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY shadowtracer/intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shadowtracer/intel/shadowtracer_intel ./shadowtracer_intel
COPY shadowtracer/intel/run_ti_sync.py ./
CMD ["python", "run_ti_sync.py"]
