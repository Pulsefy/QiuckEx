-- =============================================================================
-- Notification engine tables
-- =============================================================================

-- ---------------------------------------------------------------------------
-- notification_preferences
-- ---------------------------------------------------------------------------
-- One row per (public_key, channel) combination.
-- Channels: 'email' | 'push' | 'webhook'

CREATE TABLE IF NOT EXISTS notification_preferences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  public_key TEXT NOT NULL,                -- Stellar public key of the user
  channel TEXT NOT NULL                    -- 'email' | 'push' | 'webhook'
    CHECK (channel IN ('email', 'push', 'webhook')),

  -- Channel-specific destination
  email TEXT,                              -- required when channel = 'email'
  push_token TEXT,                         -- Expo push token; required when channel = 'push'
  webhook_url TEXT,                        -- required when channel = 'webhook'

  -- Event subscriptions (null = all events)
  events TEXT[] DEFAULT NULL,              -- e.g. ARRAY['EscrowDeposited','payment.received']

  -- Amount threshold filter: only notify when abs(amount) >= threshold (in stroops)
  min_amount_stroops BIGINT DEFAULT 0,

  enabled BOOLEAN NOT NULL DEFAULT TRUE,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- One preference row per (public_key, channel) pair
  CONSTRAINT notification_preferences_unique UNIQUE (public_key, channel)
);

CREATE INDEX IF NOT EXISTS notification_preferences_public_key_idx
  ON notification_preferences (public_key);

COMMENT ON TABLE notification_preferences IS
  'Per-user, per-channel notification preferences with event filters and amount thresholds.';

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_notification_preferences_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_notification_preferences_updated_at
  BEFORE UPDATE ON notification_preferences
  FOR EACH ROW EXECUTE FUNCTION update_notification_preferences_updated_at();

-- ---------------------------------------------------------------------------
-- notification_log
-- ---------------------------------------------------------------------------
-- Tracks every notification delivery attempt (for retries, auditing).

CREATE TABLE IF NOT EXISTS notification_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  public_key TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('email', 'push', 'webhook')),
  event_type TEXT NOT NULL,                -- e.g. 'EscrowDeposited'
  event_id TEXT NOT NULL,                  -- paging_token or tx_hash

  status TEXT NOT NULL DEFAULT 'pending'   -- 'pending' | 'sent' | 'failed'
    CHECK (status IN ('pending', 'sent', 'failed')),

  attempts INT NOT NULL DEFAULT 0,
  last_error TEXT,                         -- last failure message if any
  provider_message_id TEXT,               -- provider-side message ID on success

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Idempotency: same event should not produce duplicate log rows per channel
  CONSTRAINT notification_log_unique UNIQUE (public_key, channel, event_id, event_type)
);

CREATE INDEX IF NOT EXISTS notification_log_public_key_idx ON notification_log (public_key);
CREATE INDEX IF NOT EXISTS notification_log_status_idx ON notification_log (status);
CREATE INDEX IF NOT EXISTS notification_log_event_type_idx ON notification_log (event_type);

CREATE TRIGGER trg_notification_log_updated_at
  BEFORE UPDATE ON notification_log
  FOR EACH ROW EXECUTE FUNCTION update_notification_preferences_updated_at();

COMMENT ON TABLE notification_log IS
  'Delivery log for every notification attempt. Supports retry and audit queries.';