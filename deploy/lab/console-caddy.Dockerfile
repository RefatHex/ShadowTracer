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
