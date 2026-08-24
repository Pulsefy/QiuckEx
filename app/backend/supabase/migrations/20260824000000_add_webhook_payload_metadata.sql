-- BE-87: Add payload_metadata column to notification_log and indexes for filtered history queries

ALTER TABLE notification_log
  ADD COLUMN IF NOT EXISTS payload_metadata JSONB;

COMMENT ON COLUMN notification_log.payload_metadata IS
  'JSON metadata/payload associated with the notification attempt.';

CREATE INDEX IF NOT EXISTS idx_notification_log_filters
  ON notification_log (public_key, channel, status, event_type, created_at DESC, id DESC)
  WHERE channel = 'webhook';
