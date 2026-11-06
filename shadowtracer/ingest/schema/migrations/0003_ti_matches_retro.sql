-- Phase 6.4: retro-hunt matches (a scheduled job matching NEW IOCs against the last N days of
-- stored events) are marked retro = true; live ti-matcher and VirusTotal rows stay false.
ALTER TABLE __DATABASE__.ti_matches ON CLUSTER lab_cluster
    ADD COLUMN IF NOT EXISTS retro Bool DEFAULT false;
