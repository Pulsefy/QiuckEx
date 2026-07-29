-- Payment Link Token Security — Issue #770
--
-- Adds short-lived, one-time-use token support to payment links so that
-- payment parameters are not embedded in query strings where they can
-- leak via referrer headers, browser history, or server logs.

CREATE TABLE IF NOT EXISTS payment_link_tokens (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- The token value itself (opaque, high-entropy, URL-safe).
  token           TEXT        NOT NULL UNIQUE,

  -- Link to the payment_links row (nullable for stateless links).
  link_id         UUID        REFERENCES payment_links (id) ON DELETE SET NULL,

  -- Denormalised payment context so the token can be resolved without
  -- joining payment_links (supports stateless generated links too).
  owner_public_key      TEXT,
  destination_public_key TEXT,
  amount           TEXT        NOT NULL,
  asset_code       TEXT        NOT NULL DEFAULT 'XLM',
  asset_issuer     TEXT,
  memo             TEXT,
  memo_type        TEXT,
  username         TEXT,
  accepted_assets  JSONB,

  -- Lifecycle.
  status           TEXT        NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'consumed', 'revoked', 'expired')),

  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL,
  consumed_at      TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ,
  rotated_to       TEXT        REFERENCES payment_link_tokens (token) ON DELETE SET NULL,

  -- Tracking.
  created_by_ip    TEXT,
  created_by_ua    TEXT
);

-- Fast lookup by token value.
CREATE INDEX idx_payment_link_tokens_token
  ON payment_link_tokens (token);

-- Expiry sweep support: find active non-expired tokens.
CREATE INDEX idx_payment_link_tokens_active_expires
  ON payment_link_tokens (expires_at)
  WHERE status = 'active';

-- Upsert support for token rotation (find by link_id).
CREATE INDEX idx_payment_link_tokens_link_id
  ON payment_link_tokens (link_id)
  WHERE status = 'active';
