-- Create receipts table to persist fee snapshots for transaction detail pages

CREATE TABLE IF NOT EXISTS transaction_receipts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tx_hash TEXT NOT NULL UNIQUE,
  network_fee TEXT NOT NULL,
  platform_fee TEXT NOT NULL,
  total_fee TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS transaction_receipts_tx_hash_idx ON transaction_receipts (tx_hash);

COMMENT ON TABLE transaction_receipts IS 'Persists fee breakdowns and receipt details for on-chain transactions.';
COMMENT ON COLUMN transaction_receipts.tx_hash IS 'The Stellar transaction hash.';
COMMENT ON COLUMN transaction_receipts.network_fee IS 'The network fee paid (usually in stroops or XLM).';
COMMENT ON COLUMN transaction_receipts.platform_fee IS 'The platform fee charged.';
COMMENT ON COLUMN transaction_receipts.total_fee IS 'The total effective fee.';
