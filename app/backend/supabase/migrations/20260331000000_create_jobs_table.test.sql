-- =============================================================================
-- Test queries for jobs table migration
-- =============================================================================
-- This file contains test queries to verify the jobs table schema.
-- Run these after applying the migration to verify it works correctly.

-- Test 1: Insert a sample job
INSERT INTO jobs (type, payload, max_attempts)
VALUES (
  'webhook_delivery',
  '{"webhookUrl": "https://example.com/webhook", "eventType": "payment.received"}'::jsonb,
  5
);

-- Test 2: Query pending jobs
SELECT id, type, status, scheduled_at
FROM jobs
WHERE status = 'pending'
  AND scheduled_at <= NOW()
ORDER BY scheduled_at ASC;

-- Test 3: Update job to running with visibility timeout
UPDATE jobs
SET status = 'running',
    started_at = NOW(),
    visibility_timeout = NOW() + INTERVAL '5 minutes'
WHERE id = (SELECT id FROM jobs LIMIT 1);

-- Test 4: Query dead letter queue view
SELECT * FROM dead_letter_queue;

-- Test 5: Verify indexes exist
SELECT
  schemaname,
  tablename,
  indexname,
  indexdef
FROM pg_indexes
WHERE tablename = 'jobs'
ORDER BY indexname;

-- Test 6: Verify status constraint
-- This should fail with a check constraint violation
-- INSERT INTO jobs (type, payload, status, max_attempts)
-- VALUES ('test', '{}'::jsonb, 'invalid_status', 1);

-- Cleanup test data
DELETE FROM jobs WHERE type = 'webhook_delivery';
