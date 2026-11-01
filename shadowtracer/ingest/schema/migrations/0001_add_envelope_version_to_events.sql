-- Phase 5.6 Item 5: first real migration through the new mechanism.
-- Records which Kafka envelope_version (Item 4) produced each row -
-- schema only here; populating it with real per-row values is a
-- separate, not-yet-done change to the normalizer/writer, out of scope
-- for proving the migration mechanism itself. Nullable with no default
-- so existing rows (and rows inserted before the normalizer is ever
-- updated to populate it) read back as NULL, not a misleading 0/1.
ALTER TABLE __DATABASE__.events ON CLUSTER lab_cluster
    ADD COLUMN IF NOT EXISTS envelope_version Nullable(UInt8);
