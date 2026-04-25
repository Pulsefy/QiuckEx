-- =============================================================================
-- Refund & Reversal Workflow (BE-12)
-- =============================================================================
-- refund_attempts  : one row per logical refund request (idempotency-keyed)
-- refund_audit_log : append-only audit trail (who / why / when per transition)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- refund_attempts
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refund_attempts (
  id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key   TEXT         NOT NULL,
  entity_type       TEXT         NOT NULL CHECK (entity_type IN ('payment', 'escrow', 'link')),
  entity_id         TEXT         NOT NULL,
  reason_code       TEXT         NOT NULL,
  notes             TEXT,
  status            TEXT         NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending', 'approved', 'rejected', 'failed')),
  actor_id          TEXT         NOT NULL,
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT uq_refund_idempotency_key UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_refund_attempts_entity
  ON refund_attempts (entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_refund_attempts_status
  ON refund_attempts (status);

-- ---------------------------------------------------------------------------
-- refund_audit_log
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refund_audit_log (
  id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  refund_id   UUID         NOT NULL REFERENCES refund_attempts (id) ON DELETE CASCADE,
  actor_id    TEXT         NOT NULL,
  action      TEXT         NOT NULL,
  reason_code TEXT,
  notes       TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refund_audit_log_refund_id
  ON refund_audit_log (refund_id);
