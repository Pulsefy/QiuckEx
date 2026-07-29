-- Add expires_at column to support "ending soon" sorting
-- Default: 7 days from creation (standard listing duration)
ALTER TABLE username_marketplace
  ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '7 days';

-- Index for efficient "ending soon" queries
CREATE INDEX IF NOT EXISTS idx_username_marketplace_expires_at
  ON username_marketplace (expires_at ASC)
  WHERE status = 'active';

-- Backfill existing rows: set expires_at to 7 days from creation
UPDATE username_marketplace
  SET expires_at = created_at + interval '7 days'
  WHERE expires_at IS NULL;
