-- Webhook secret for payload signing

ALTER TABLE notification_preferences
ADD COLUMN IF NOT EXISTS webhook_secret TEXT;

ALTER TABLE notification_log
ADD COLUMN IF NOT EXISTS webhook_response_status INT,
ADD COLUMN IF NOT EXISTS webhook_response_body TEXT,
ADD COLUMN IF NOT EXISTS webhook_delivered_at TIMESTAMPTZ;

COMMENT ON COLUMN notification_preferences.webhook_secret IS
  'Secret key used to sign webhook payloads with HMAC-SHA256. Only set for webhook channel.';

COMMENT ON COLUMN notification_log.webhook_response_status IS
  'HTTP status code returned by webhook endpoint.';

COMMENT ON COLUMN notification_log.webhook_response_body IS
  'Response body from webhook endpoint (truncated if too long).';

COMMENT ON COLUMN notification_log.webhook_delivered_at IS
  'Timestamp when webhook was successfully delivered.';

CREATE INDEX IF NOT EXISTS notification_preferences_webhook_idx
  ON notification_preferences (channel, enabled)
  WHERE channel = 'webhook' AND enabled = TRUE;

CREATE INDEX IF NOT EXISTS notification_log_webhook_status_idx
  ON notification_log (channel, status, created_at)
  WHERE channel = 'webhook';
