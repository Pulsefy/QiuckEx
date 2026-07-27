-- BE-28: Soroban Event Indexer v1
-- Adds normalized tables for all contract event domains and a ledger-range
-- checkpoint table for the batch poller.

-- ─── Ledger range checkpoints ────────────────────────────────────────────────
-- Tracks the highest fully-processed ledger for each contract so the poller
-- can resume without re-scanning already-indexed ranges.

CREATE TABLE IF NOT EXISTS indexer_checkpoints (
  contract_id  TEXT        NOT NULL,
  last_ledger  BIGINT      NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (contract_id)
);

COMMENT ON TABLE indexer_checkpoints IS
  'Durable ledger-range checkpoint for the Soroban event batch poller (BE-28).';

-- ─── Privacy events ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS privacy_events (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type         TEXT        NOT NULL,   -- "PrivacyToggled"
  owner              TEXT        NOT NULL,
  enabled            BOOLEAN     NOT NULL,
  schema_version     INT         NOT NULL DEFAULT 1,
  contract_timestamp BIGINT      NOT NULL,
  tx_hash            TEXT        NOT NULL,
  ledger_sequence    BIGINT      NOT NULL,
  paging_token       TEXT        NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT privacy_events_unique UNIQUE (tx_hash, event_type, owner)
);

CREATE INDEX IF NOT EXISTS privacy_events_owner_idx          ON privacy_events (owner);
CREATE INDEX IF NOT EXISTS privacy_events_ledger_idx         ON privacy_events (ledger_sequence);

COMMENT ON TABLE privacy_events IS 'PrivacyToggled events from the QuickEx Soroban contract.';

-- ─── Admin events ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin_events (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type         TEXT        NOT NULL,   -- "ContractPaused" | "AdminChanged" | "ContractUpgraded" | ...
  payload            JSONB       NOT NULL,   -- event-specific fields
  schema_version     INT         NOT NULL DEFAULT 1,
  contract_timestamp BIGINT      NOT NULL,
  tx_hash            TEXT        NOT NULL,
  ledger_sequence    BIGINT      NOT NULL,
  paging_token       TEXT        NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT admin_events_unique UNIQUE (tx_hash, event_type)
);

CREATE INDEX IF NOT EXISTS admin_events_event_type_idx ON admin_events (event_type);
CREATE INDEX IF NOT EXISTS admin_events_ledger_idx     ON admin_events (ledger_sequence);

COMMENT ON TABLE admin_events IS 'Admin action events from the QuickEx Soroban contract.';

-- ─── Stealth events ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS stealth_events (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type         TEXT        NOT NULL,   -- "EphemeralKeyRegistered" | "StealthWithdrawn"
  stealth_address    TEXT        NOT NULL,
  counterparty       TEXT        NOT NULL,   -- eph_pub (registered) or recipient (withdrawn)
  token              TEXT,
  amount             TEXT,
  expires_at         TIMESTAMPTZ,
  schema_version     INT         NOT NULL DEFAULT 1,
  contract_timestamp BIGINT      NOT NULL,
  tx_hash            TEXT        NOT NULL,
  ledger_sequence    BIGINT      NOT NULL,
  paging_token       TEXT        NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT stealth_events_unique UNIQUE (tx_hash, event_type, stealth_address)
);

CREATE INDEX IF NOT EXISTS stealth_events_stealth_address_idx ON stealth_events (stealth_address);
CREATE INDEX IF NOT EXISTS stealth_events_ledger_idx          ON stealth_events (ledger_sequence);

COMMENT ON TABLE stealth_events IS 'Stealth address events from the QuickEx Soroban contract.';

-- ─── Escrow events: add schema_version column (idempotent) ───────────────────

ALTER TABLE escrow_events
  ADD COLUMN IF NOT EXISTS schema_version INT NOT NULL DEFAULT 1;
