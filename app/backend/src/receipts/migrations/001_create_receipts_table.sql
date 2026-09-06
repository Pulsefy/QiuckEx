--- 001_create_receipts_table.sql
CREATE TABLE IF NOT EXISTS receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tx_hash text NOT NULL,
  operation_index integer NOT NULL DEFAULT 0,
  network text NOT NULL,
  receipt json NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT receipts_tx_op_network_key UNIQUE (tx_hash, operation_index, network)
);


CREATE INDEX IF NOT EXISTS idx_receipts_tx_hash ON receipts (tx_hash);
CREATE INDEX IF NOT EXISTS idx_receipts_network ON receipts (network);
