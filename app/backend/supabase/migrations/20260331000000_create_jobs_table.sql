-- =============================================================================
-- Job Queue System
-- =============================================================================

-- ---------------------------------------------------------------------------
-- jobs
-- ---------------------------------------------------------------------------
-- Unified job queue for background processing (webhooks, recurring payments,
-- exports, reconciliation, Stellar reconnection).

CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  type TEXT NOT NULL,                      -- Job type: 'webhook_delivery', 'recurring_payment', etc.
  payload JSONB NOT NULL,                  -- Job-specific payload data

  status TEXT NOT NULL DEFAULT 'pending'   -- Job execution status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),

  attempts INTEGER NOT NULL DEFAULT 0,     -- Current retry attempt count
  max_attempts INTEGER NOT NULL,           -- Maximum retry attempts (0 = unlimited)

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  scheduled_at TIMESTAMPTZ NOT NULL DEFAULT now(),  -- When job should execute
  started_at TIMESTAMPTZ,                  -- When job execution began
  completed_at TIMESTAMPTZ,                -- When job finished (success/failure/cancelled)

  failure_reason TEXT,                     -- Error message if job failed
  visibility_timeout TIMESTAMPTZ           -- Lock expiry for running jobs
);

-- ---------------------------------------------------------------------------
-- Indexes for efficient job queries
-- ---------------------------------------------------------------------------

-- Primary query: find due jobs that are unlocked
CREATE INDEX IF NOT EXISTS idx_jobs_status_scheduled
  ON jobs(status, scheduled_at)
  WHERE status IN ('pending', 'running');

-- Filter jobs by type and status
CREATE INDEX IF NOT EXISTS idx_jobs_type_status
  ON jobs(type, status);

-- Sort jobs by creation time (for admin UI)
CREATE INDEX IF NOT EXISTS idx_jobs_created_at
  ON jobs(created_at DESC);

-- Find jobs with expired visibility timeout
CREATE INDEX IF NOT EXISTS idx_jobs_visibility_timeout
  ON jobs(visibility_timeout)
  WHERE status = 'running';

-- ---------------------------------------------------------------------------
-- dead_letter_queue view
-- ---------------------------------------------------------------------------
-- Shows failed jobs that have exhausted all retry attempts

CREATE OR REPLACE VIEW dead_letter_queue AS
SELECT * FROM jobs
WHERE status = 'failed' AND attempts >= max_attempts;

COMMENT ON TABLE jobs IS
  'Unified job queue for background processing with retry policies and visibility timeout locking.';

COMMENT ON VIEW dead_letter_queue IS
  'Failed jobs that have exhausted all retry attempts and require manual intervention.';
