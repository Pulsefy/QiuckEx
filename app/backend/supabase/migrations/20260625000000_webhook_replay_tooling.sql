-- BE-36: Webhook replay tooling — DLQ status + auditable replay log.

-- Allow dlq status on notification_log (dead-letter after exhausting retries).
ALTER TABLE notification_log
  DROP CONSTRAINT IF EXISTS notification_log_status_check;

ALTER TABLE notification_log
  ADD CONSTRAINT notification_log_status_check
  CHECK (status IN ('pending', 'sent', 'failed', 'dlq'));

COMMENT ON COLUMN notification_log.status IS
  'pending | sent | failed (retryable) | dlq (exhausted retries, inspectable)';

-- Auditable log of manual replay API calls.
CREATE TABLE IF NOT EXISTS webhook_replay_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  webhook_id UUID NOT NULL,
  public_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_id TEXT NOT NULL,

  status TEXT NOT NULL CHECK (status IN ('queued', 'succeeded', 'failed', 'rejected')),
  reason TEXT,
  triggered_by TEXT NOT NULL DEFAULT 'api',
  delivery_success BOOLEAN,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhook_replay_log_webhook_created
  ON webhook_replay_log (webhook_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_replay_log_event
  ON webhook_replay_log (public_key, event_type, event_id, created_at DESC);

COMMENT ON TABLE webhook_replay_log IS
  'Audit trail for manual webhook replay requests (BE-36).';
