-- BE-60: GitHub Branch/PR Deployment Metadata Sync
--
-- Stores deployment metadata (branch, PR number, commit SHA, preview URL,
-- status) ingested from GitHub branch/PR deployment events so admin tooling
-- can answer "what is deployed for branch X / PR Y" without scraping GitHub.
--
-- Idempotency: a unique index on (branch_name, commit_sha) makes duplicate
-- webhook deliveries of the same commit a no-op update rather than a new row.

CREATE TABLE IF NOT EXISTS branch_deployments (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  branch_name   TEXT        NOT NULL,
  pr_number     INTEGER,
  commit_sha    TEXT        NOT NULL,
  preview_url   TEXT        NOT NULL,
  status        TEXT        NOT NULL DEFAULT 'deployed' CHECK (
                    status IN ('in_progress', 'deployed', 'failed', 'cancelled')
                  ),
  environment   TEXT        NOT NULL DEFAULT 'preview',

  -- Timestamp of the deployment event (from the source webhook/poll), used
  -- to reject stale out-of-order deliveries.
  delivered_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE branch_deployments IS
  'Deployment metadata synced from GitHub branch/PR deployment events.';
COMMENT ON COLUMN branch_deployments.pr_number IS
  'Pull request number when the deployment belongs to a PR branch; NULL for plain branch deployments.';
COMMENT ON COLUMN branch_deployments.delivered_at IS
  'Timestamp of the source deployment event; stale deliveries (older than the newest stored) are rejected.';

-- Idempotent duplicate-delivery key: one row per (branch, commit).
CREATE UNIQUE INDEX IF NOT EXISTS uq_branch_deployments_branch_commit
  ON branch_deployments (branch_name, commit_sha);

CREATE INDEX IF NOT EXISTS idx_branch_deployments_branch
  ON branch_deployments (branch_name, delivered_at DESC);

CREATE INDEX IF NOT EXISTS idx_branch_deployments_pr
  ON branch_deployments (pr_number, delivered_at DESC);
