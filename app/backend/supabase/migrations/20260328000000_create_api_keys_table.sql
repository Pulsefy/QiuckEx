-- =============================================================================
-- API Keys Management
-- =============================================================================
-- Supports developer API key lifecycle: create, revoke, rotate.
-- Granular scopes: links:read, links:write, transactions:read, usernames:read
-- Usage tracking and monthly quota enforcement.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- api_keys
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS api_keys (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT         NOT NULL,
  key_hash        TEXT         NOT NULL,           -- bcrypt hash of the raw key
  key_prefix      TEXT         NOT NULL,           -- first ~11 chars for fast lookup
  scopes          TEXT[]       NOT NULL DEFAULT '{}',
  owner_id        TEXT,                            -- wallet address or user identifier
  is_active       BOOLEAN      NOT NULL DEFAULT true,
  request_count   INTEGER      NOT NULL DEFAULT 0,
  monthly_quota   INTEGER      NOT NULL DEFAULT 10000,
  last_used_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Index for guard validation (prefix-based candidate lookup)
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix
  ON api_keys (key_prefix)
  WHERE is_active = true;

-- Index for listing keys by owner
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_id
  ON api_keys (owner_id)
  WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- Helper: increment usage atomically without a SELECT + UPDATE race
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION increment_api_key_usage(key_id UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE api_keys
  SET
    request_count = request_count + 1,
    last_used_at  = now(),
    updated_at    = now()
  WHERE id = key_id AND is_active = true;
END;
$$;
