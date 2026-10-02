# shadowtracer/

All original ShadowTracer code lives here.

Everything outside this directory is inherited Wazuh (GPLv2), changed only
when necessary. Every such change is recorded in [UPSTREAM.md](../UPSTREAM.md).

## Modules

- `ingest/` — event ingestion
- `correlate/` — correlation / classic rules integration
- `fingerprint/` — asset/host fingerprinting
- `intel/` — threat intelligence
- `yara/` — YARA-X file scanning
- `vuln/` — vulnerability data
- `ml/` — machine learning features
- `forecast/` — forecasting
- `soar/` — security orchestration, automation and response
- `console/` — our own console (replaces Wazuh dashboard/indexer)
- `common/` — shared code used across the above modules

`ingest/` has real code as of Phase 3 (shipper, normaliser, writer - see
its own docs below). Every other module is still empty scaffolding.

## Docs

- [docs/DECISIONS.md](docs/DECISIONS.md) — architecture decisions
- [docs/DEV_SETUP.md](docs/DEV_SETUP.md) — dev environment setup
- [docs/PHASE3_DATA_PLATFORM.md](docs/PHASE3_DATA_PLATFORM.md) — Kafka/ClickHouse/PostgreSQL data platform (`ingest/`)
