-- Cursor-based pagination indexes
-- These composite indexes ensure deterministic ordering and efficient
-- cursor pagination across all list endpoints.  Each index covers the
-- (created_at DESC, id DESC) pattern used by cursor-based pagination
-- with `created_at` as the primary sort and `id` as the tiebreaker.

-- api_keys: filtered by is_active, optionally by owner_id
CREATE INDEX IF NOT EXISTS idx_api_keys_active_created_at_id
  ON api_keys (is_active, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_api_keys_owner_active_created_at_id
  ON api_keys (owner_id, is_active, created_at DESC, id DESC);

-- recurring_payment_links: filtered by status, optionally by username/destination
CREATE INDEX IF NOT EXISTS idx_recurring_payment_links_created_at_id
  ON recurring_payment_links (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_recurring_payment_links_status_created_at_id
  ON recurring_payment_links (status, created_at DESC, id DESC);

-- refund_attempts: ordered by created_at DESC
CREATE INDEX IF NOT EXISTS idx_refund_attempts_created_at_id
  ON refund_attempts (created_at DESC, id DESC);

-- username_marketplace: filtered by status='active'
CREATE INDEX IF NOT EXISTS idx_username_marketplace_status_created_at_id
  ON username_marketplace (status, created_at DESC, id DESC);

-- username_bids: filtered by listing_id
CREATE INDEX IF NOT EXISTS idx_username_bids_listing_created_at_id
  ON username_bids (listing_id, created_at DESC, id DESC);

-- notification_preferences: filtered by public_key + channel='webhook'
CREATE INDEX IF NOT EXISTS idx_notification_prefs_pk_channel_created_at_id
  ON notification_preferences (public_key, channel, created_at DESC, id DESC);

-- notification_log: filtered by public_key + channel='webhook'
CREATE INDEX IF NOT EXISTS idx_notification_log_pk_channel_created_at_id
  ON notification_log (public_key, channel, created_at DESC, id DESC);
