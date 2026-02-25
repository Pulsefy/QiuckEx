-- =============================================================================
-- Migration: 001_reconciliation_tables
-- Creates escrow_records and payment_records tables used by the reconciliation
-- worker to track on-chain state versus database state.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- escrow_records
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS escrow_records (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  contract_address    TEXT NOT NULL,                          -- Stellar account acting as escrow
  status              TEXT NOT NULL DEFAULT 'pending',        -- pending | active | claimed | expired | cancelled | irreconcilable
  amount              NUMERIC(20, 7) NOT NULL,
  asset               TEXT NOT NULL DEFAULT 'XLM',           -- XLM or CODE:ISSUER
  from_address        TEXT NOT NULL,                          -- Stellar public key of sender
  to_address          TEXT NOT NULL,                          -- Stellar public key of recipient
  expires_at          TIMESTAMPTZ,                            -- Optional time-bound expiry
  reconciliation_note TEXT,                                   -- Populated by worker on irreconcilable state
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index for fast retrieval of actionable escrows
CREATE INDEX IF NOT EXISTS idx_escrow_records_reconcilable
  ON escrow_records (status, updated_at)
  WHERE status IN ('pending', 'active');

-- ---------------------------------------------------------------------------
-- payment_records
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payment_records (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stellar_tx_hash     TEXT NOT NULL UNIQUE,                   -- Stellar transaction hash
  status              TEXT NOT NULL DEFAULT 'pending',        -- pending | processing | paid | failed | irreconcilable
  amount              NUMERIC(20, 7) NOT NULL,
  asset               TEXT NOT NULL DEFAULT 'XLM',
  from_address        TEXT NOT NULL,
  to_address          TEXT NOT NULL,
  memo                TEXT,
  reconciliation_note TEXT,                                   -- Populated by worker on irreconcilable state
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index for fast retrieval of actionable payments
CREATE INDEX IF NOT EXISTS idx_payment_records_reconcilable
  ON payment_records (status, updated_at)
  WHERE status IN ('pending', 'processing');

-- ---------------------------------------------------------------------------
-- updated_at trigger (shared function)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_escrow_records_updated_at
  BEFORE UPDATE ON escrow_records
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_payment_records_updated_at
  BEFORE UPDATE ON payment_records
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
