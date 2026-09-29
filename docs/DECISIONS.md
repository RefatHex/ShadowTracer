# Decisions

- **Base:** Wazuh 4.14.8 with the classic (non-indexer) rules engine.
- **No Wazuh indexer or dashboard**: replaced by our own storage and console.
- **Storage:** ClickHouse for events, PostgreSQL for application data.
- **Console:** our own, not the Wazuh dashboard.
- **File scanning:** YARA-X.

## Open decisions

- Capacity target
- Queue technology
- ML feature location
- Tenancy model
- Licensing model
