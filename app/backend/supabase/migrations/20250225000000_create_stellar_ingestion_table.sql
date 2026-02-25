-- Stellar ingestion: Cursors table
-- Tracks the last processed Horizon paging token per stream so the service
-- can resume exactly where it left off after a restart.

CREATE TABLE IF NOT EXISTS cursors (
  id TEXT PRIMARY KEY,                         -- e.g. "contract:<CONTRACT_ID>"
  paging_token TEXT NOT NULL,                  -- last processed Horizon paging token
  ledger_sequence BIGINT,                      -- optional: ledger number for reference
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE cursors IS 'Tracks last ingested Horizon paging token per stream for idempotent resumption.';
COMMENT ON COLUMN cursors.id IS 'Stream identifier, e.g. "contract:<CONTRACT_ID>" or "account:<PUBLIC_KEY>".';
COMMENT ON COLUMN cursors.paging_token IS 'Horizon paging_token of the last successfully processed record.';

-- Escrow events table
-- Canonical store for domain events parsed from Soroban contract events.

CREATE TABLE IF NOT EXISTS escrow_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL,                    -- "EscrowDeposited" | "EscrowWithdrawn" | "EscrowRefunded"
  commitment TEXT NOT NULL,                    -- hex-encoded BytesN<32>
  owner TEXT NOT NULL,                         -- Stellar public key
  token TEXT NOT NULL,                         -- token contract address
  amount TEXT NOT NULL,                        -- i128 as text to avoid JS precision loss
  expires_at TIMESTAMPTZ,                      -- only present for EscrowDeposited
  contract_timestamp BIGINT NOT NULL,          -- ledger timestamp from the contract event
  tx_hash TEXT NOT NULL,                       -- transaction hash
  ledger_sequence BIGINT NOT NULL,
  paging_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Idempotency: same event on same tx cannot be inserted twice
  CONSTRAINT escrow_events_tx_hash_event_type_unique UNIQUE (tx_hash, commitment, event_type)
);

CREATE INDEX IF NOT EXISTS escrow_events_commitment_idx ON escrow_events (commitment);
CREATE INDEX IF NOT EXISTS escrow_events_owner_idx ON escrow_events (owner);
CREATE INDEX IF NOT EXISTS escrow_events_event_type_idx ON escrow_events (event_type);
CREATE INDEX IF NOT EXISTS escrow_events_ledger_sequence_idx ON escrow_events (ledger_sequence);

COMMENT ON TABLE escrow_events IS 'Domain events ingested from the QuickEx Soroban contract.';