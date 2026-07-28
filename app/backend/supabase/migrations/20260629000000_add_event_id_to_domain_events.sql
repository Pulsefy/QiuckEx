-- BE-XX: Add event_id column to all domain event tables
-- This column stores a deterministic, content-addressed SHA-256 identifier
-- computed from the same identity fields as each table's existing UNIQUE
-- constraint, making it safe to use for client-side deduplication, change
-- feeds, and outbox patterns.
--
-- NOTE: No UNIQUE constraint is added here. The column is intentionally
-- nullable and non-unique until it is backfilled for historical rows.
-- A follow-up migration should:
--   1. Run: UPDATE <table> SET event_id = <recomputed> WHERE event_id IS NULL;
--   2. Add: ALTER TABLE <table> ALTER COLUMN event_id SET NOT NULL;
--   3. Add: ALTER TABLE <table> ADD CONSTRAINT <table>_event_id_unique UNIQUE (event_id);
-- Adding a premature UNIQUE constraint on a partially-populated column would
-- reject any row whose event_id is NULL (or collide on duplicate NULLs
-- depending on DB settings), so we defer it to a separate migration.

ALTER TABLE escrow_events  ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE admin_events   ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE privacy_events ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE stealth_events ADD COLUMN IF NOT EXISTS event_id TEXT;

-- Non-unique indexes on event_id for efficient lookup / fan-out queries.
-- Unique enforcement is deferred until the column is fully backfilled.
CREATE INDEX IF NOT EXISTS escrow_events_event_id_idx  ON escrow_events  (event_id);
CREATE INDEX IF NOT EXISTS admin_events_event_id_idx   ON admin_events   (event_id);
CREATE INDEX IF NOT EXISTS privacy_events_event_id_idx ON privacy_events (event_id);
CREATE INDEX IF NOT EXISTS stealth_events_event_id_idx ON stealth_events (event_id);
