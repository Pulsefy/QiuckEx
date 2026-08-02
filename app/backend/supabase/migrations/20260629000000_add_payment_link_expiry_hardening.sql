-- Add expiry processing columns and audit table for payment_links

ALTER TABLE IF EXISTS payment_links
  ADD COLUMN IF NOT EXISTS expiry_processed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS expiry_processed_by TEXT,
  ADD COLUMN IF NOT EXISTS expiry_note TEXT;

CREATE TABLE IF NOT EXISTS payment_link_expiry_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  link_id UUID NOT NULL REFERENCES payment_links(id) ON DELETE CASCADE,
  previous_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_by TEXT,
  run_id TEXT,
  note TEXT
);

CREATE INDEX IF NOT EXISTS idx_payment_link_expiry_audit_processed
  ON payment_link_expiry_audit (processed_at DESC);
