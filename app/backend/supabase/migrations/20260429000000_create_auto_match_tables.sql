-- Automated Reconciliation Engine (Auto-Match) — Issue #394
--
-- Creates two tables:
--   payment_links         – open payment requests awaiting on-chain fulfillment.
--   unmatched_transactions – transactions the engine couldn't auto-match; queued for
--                            manual operator review.

-- ─── payment_links ────────────────────────────────────────────────────────────
-- Stores payment links created by QuickEx users. The auto-match engine queries
-- this table to find candidate links for each incoming Stellar transaction.

CREATE TABLE IF NOT EXISTS payment_links (
  id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- The QuickEx user who owns this link (the payee).
  owner_public_key      TEXT        NOT NULL,

  -- Stellar account that will receive the funds (usually the same as owner).
  destination_public_key TEXT       NOT NULL,

  -- Expected payment conditions.
  amount                TEXT        NOT NULL,        -- decimal string, e.g. "10.5000000"
  asset_code            TEXT        NOT NULL DEFAULT 'XLM',
  asset_issuer          TEXT,                        -- NULL for native XLM

  -- Memo is the primary matching signal: a unique memo enables 100 % confidence.
  memo                  TEXT,
  memo_type             TEXT        NOT NULL DEFAULT 'text'
    CHECK (memo_type IN ('text', 'id', 'hash', 'return', 'none')),

  -- Optional caller-assigned reference for idempotency.
  reference_id          TEXT        UNIQUE,

  -- Lifecycle.
  status                TEXT        NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'paid', 'expired', 'cancelled')),

  expires_at            TIMESTAMPTZ,

  -- Populated by the auto-match engine when the link is fulfilled.
  matched_tx_hash       TEXT,
  matched_at            TIMESTAMPTZ,
  match_confidence      INTEGER     CHECK (match_confidence BETWEEN 0 AND 100),

  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Primary query pattern: find open links for a given destination address.
CREATE INDEX idx_payment_links_destination_open
  ON payment_links (destination_public_key)
  WHERE status = 'open';

-- Secondary pattern: memo-based lookup (the 100 % confidence path).
CREATE INDEX idx_payment_links_memo_open
  ON payment_links (memo)
  WHERE memo IS NOT NULL AND status = 'open';

-- Expiry sweep support.
CREATE INDEX idx_payment_links_expires_open
  ON payment_links (expires_at)
  WHERE status = 'open' AND expires_at IS NOT NULL;

-- Auto-maintain updated_at on payment_links rows.
CREATE OR REPLACE FUNCTION trigger_payment_links_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER payment_links_updated_at
  BEFORE UPDATE ON payment_links
  FOR EACH ROW EXECUTE FUNCTION trigger_payment_links_set_updated_at();


-- ─── unmatched_transactions ───────────────────────────────────────────────────
-- Transactions the auto-match engine could not map to an open payment link with
-- sufficient confidence.  Operators review and resolve each entry manually.

CREATE TABLE IF NOT EXISTS unmatched_transactions (
  id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Immutable Horizon transaction details.
  tx_hash                 TEXT        NOT NULL UNIQUE,
  ledger                  BIGINT,
  source_account          TEXT        NOT NULL,
  destination_account     TEXT        NOT NULL,
  amount                  TEXT        NOT NULL,
  asset_code              TEXT        NOT NULL,
  asset_issuer            TEXT,
  memo                    TEXT,
  memo_type               TEXT,
  occurred_at             TIMESTAMPTZ NOT NULL,

  -- When this row was created by the engine.
  ingested_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Review lifecycle.
  status                  TEXT        NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'resolved', 'dismissed')),

  -- Best candidate found during scoring (NULL = no candidates above threshold).
  best_candidate_link_id  UUID        REFERENCES payment_links (id),
  best_confidence         INTEGER     CHECK (best_confidence BETWEEN 0 AND 100),

  -- Populated by an operator resolving or dismissing this entry.
  resolved_by             TEXT,
  resolved_at             TIMESTAMPTZ,
  resolution_note         TEXT
);

-- Efficient listing of pending items for the admin dashboard (newest first).
CREATE INDEX idx_unmatched_tx_pending_ingested
  ON unmatched_transactions (ingested_at DESC)
  WHERE status = 'pending';

-- Allow fast lookup of a specific hash (idempotency guard on enqueue).
-- The UNIQUE constraint already creates an index; this comment is for clarity.
