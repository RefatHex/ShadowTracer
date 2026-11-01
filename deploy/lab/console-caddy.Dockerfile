# Builds the frontend and serves it from Caddy, which also reverse-proxies
# /auth, /api, /health to the console backend replicas. Built from the
# repo root:
#   docker build -f deploy/lab/console-caddy.Dockerfile -t shadowtracer-lab/console-caddy:local .

FROM node:22-slim AS frontend-builder
WORKDIR /frontend
COPY shadowtracer/console/frontend/package.json shadowtracer/console/frontend/package-lock.json ./
RUN npm ci
COPY shadowtracer/console/frontend .
RUN npm run build

FROM caddy:2-alpine
COPY deploy/lab/Caddyfile /etc/caddy/Caddyfile
COPY --from=frontend-builder /frontend/dist /srv/frontend

# Phase 5.6 Item 9: curl -k because the Caddyfile's `tls internal` cert is
# self-signed (no real domain in the lab, see Caddyfile's own comment);
# the request is proxied straight through to the backend's /health (see
# Caddyfile's `handle /health*` block), so this also fails if the
# backend replicas it fronts are both down, not just if Caddy itself is.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD curl -ksf https://localhost:8443/health
