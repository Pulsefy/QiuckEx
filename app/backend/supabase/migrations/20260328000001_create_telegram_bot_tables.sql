-- =============================================================================
-- Telegram bot integration tables
-- =============================================================================

-- ---------------------------------------------------------------------------
-- telegram_user_mappings
-- ---------------------------------------------------------------------------
-- Maps Telegram user IDs to QuickEx public keys for notification delivery.
-- Users link their Telegram account by starting a conversation with the bot
-- and providing their QuickEx public key or username.

CREATE TABLE IF NOT EXISTS telegram_user_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  telegram_id BIGINT NOT NULL,                -- Telegram user ID
  username TEXT,                               -- Telegram username (@username without @)
  public_key TEXT NOT NULL,                   -- QuickEx public key (G...)
  
  -- Linking status
  is_verified BOOLEAN NOT NULL DEFAULT false, -- Whether user confirmed the link
  verification_code TEXT,                      -- One-time code for verification
  
  -- Notification settings
  enabled BOOLEAN NOT NULL DEFAULT true,      -- User can temporarily disable notifications
  min_amount_stroops BIGINT DEFAULT 0,        -- Minimum amount threshold in stroops
  
  -- Metadata
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_notification_at TIMESTAMPTZ,           -- Last notification sent timestamp
  
  -- Constraints
  CONSTRAINT telegram_user_mappings_telegram_id_unique UNIQUE (telegram_id),
  CONSTRAINT telegram_user_mappings_public_key_unique UNIQUE (public_key)
);

CREATE INDEX IF NOT EXISTS telegram_user_mappings_telegram_id_idx 
  ON telegram_user_mappings (telegram_id);

CREATE INDEX IF NOT EXISTS telegram_user_mappings_public_key_idx 
  ON telegram_user_mappings (public_key);

CREATE INDEX IF NOT EXISTS telegram_user_mappings_enabled_idx 
  ON telegram_user_mappings (enabled) 
  WHERE enabled = true;

COMMENT ON TABLE telegram_user_mappings IS
  'Maps Telegram users to QuickEx accounts for real-time payment notifications.';

COMMENT ON COLUMN telegram_user_mappings.is_verified IS 
  'Whether the user has confirmed the Telegram-QuickEx account link';

COMMENT ON COLUMN telegram_user_mappings.verification_code IS 
  'One-time code sent via Telegram to verify account ownership';

-- Auto-update updated_at trigger
CREATE OR REPLACE FUNCTION update_telegram_user_mappings_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_telegram_user_mappings_updated_at
  BEFORE UPDATE ON telegram_user_mappings
  FOR EACH ROW EXECUTE FUNCTION update_telegram_user_mappings_updated_at();

-- ---------------------------------------------------------------------------
-- telegram_notification_log
-- ---------------------------------------------------------------------------
-- Tracks Telegram notification delivery for monitoring and debugging.

CREATE TABLE IF NOT EXISTS telegram_notification_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  telegram_id BIGINT NOT NULL,
  public_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_id TEXT NOT NULL,
  
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'sent', 'failed')),
  
  attempts INT NOT NULL DEFAULT 0,
  last_error TEXT,
  telegram_message_id INTEGER,              -- Telegram message ID if sent
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Idempotency constraint
  CONSTRAINT telegram_notification_log_unique 
    UNIQUE (telegram_id, event_id, event_type)
);

CREATE INDEX IF NOT EXISTS telegram_notification_log_telegram_id_idx 
  ON telegram_notification_log (telegram_id);

CREATE INDEX IF NOT EXISTS telegram_notification_log_status_idx 
  ON telegram_notification_log (status);

CREATE TRIGGER trg_telegram_notification_log_updated_at
  BEFORE UPDATE ON telegram_notification_log
  FOR EACH ROW EXECUTE FUNCTION update_telegram_user_mappings_updated_at();

COMMENT ON TABLE telegram_notification_log IS
  'Delivery log for Telegram notifications. Tracks success/failure for retry logic.';
