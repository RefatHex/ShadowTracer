"""SOAR (Phase 9): incident-level automated response on Wazuh active response.

Its own worker (soar_worker.py) polls incidents from Postgres off the hot path, runs the
confidence gate and safety rails, and records every intended/taken action in soar_actions,
audited. Containment dispatch is Wazuh AR via the manager API. See docs/SOAR.md.
"""
