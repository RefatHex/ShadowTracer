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

Modules are currently empty scaffolding (Phase 0). No product code yet.

## Docs

- [docs/DECISIONS.md](docs/DECISIONS.md) — architecture decisions
- [docs/DEV_SETUP.md](docs/DEV_SETUP.md) — dev environment setup
