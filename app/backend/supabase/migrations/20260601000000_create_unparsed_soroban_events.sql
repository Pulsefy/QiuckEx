-- BE-51: Retain unparsed Soroban events for schema replay.

CREATE TABLE IF NOT EXISTS unparsed_soroban_events (
  paging_token    TEXT        PRIMARY KEY,
  contract_id     TEXT        NOT NULL,
  ledger          BIGINT      NOT NULL,
  transaction_hash TEXT       NOT NULL,
  event_name      TEXT,
  schema_version  INT,
  reason          TEXT        NOT NULL CHECK (reason IN ('unknown_schema_version', 'parse_failure')),
  raw_topics      JSONB       NOT NULL,
  raw_payload     JSONB       NOT NULL,
  raw_event       JSONB       NOT NULL,
  error_message   TEXT,
  status          TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'replayed')),
  attempts        INT         NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS unparsed_soroban_events_status_ledger_idx
  ON unparsed_soroban_events (status, ledger);

CREATE INDEX IF NOT EXISTS unparsed_soroban_events_contract_idx
  ON unparsed_soroban_events (contract_id);

COMMENT ON TABLE unparsed_soroban_events IS
  'Raw Soroban events retained when schema versions are unknown or parsing fails.';
