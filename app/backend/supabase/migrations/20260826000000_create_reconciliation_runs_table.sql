-- =============================================================================
-- Reconciliation Runs History
-- =============================================================================
-- Persists historical data for reconciliation runs, per-run drift details,
-- and run status (success / failure) for operator auditing.
-- =============================================================================

CREATE TABLE IF NOT EXISTS reconciliation_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ NOT NULL,
  duration_ms INTEGER NOT NULL,
  status TEXT NOT NULL,
  error_message TEXT,
  report JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for ordering history by completion/run time descending
CREATE INDEX IF NOT EXISTS idx_reconciliation_runs_created_at
  ON reconciliation_runs (created_at DESC);
