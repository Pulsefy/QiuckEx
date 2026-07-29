-- BE-70: Deployment Artifact Storage API
--
-- Stores signed deployment artifacts (deploy manifests, smoke test outputs,
-- registry snapshots) so contributors and operators can retrieve them for
-- traceability of any recent deployment.

CREATE TABLE IF NOT EXISTS deployment_artifacts (
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  deployment_id     TEXT        NOT NULL,
  network           TEXT        NOT NULL,
  artifact_type     TEXT        NOT NULL CHECK (
                        artifact_type IN ('deploy_manifest', 'smoke_report', 'registry_snapshot')
                      ),

  -- Content is stored inline (base64) for now; checksum lets clients verify
  -- integrity independent of storage backend.
  content           TEXT        NOT NULL,
  content_encoding  TEXT        NOT NULL DEFAULT 'base64',
  checksum_sha256   TEXT        NOT NULL,
  size_bytes        INTEGER     NOT NULL,

  uploaded_by       TEXT        NOT NULL,
  metadata          JSONB       NOT NULL DEFAULT '{}'::jsonb,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_until   TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '180 days')
);

COMMENT ON TABLE deployment_artifacts IS
  'Signed deployment artifacts (manifests, smoke reports, registry snapshots) for contributor traceability.';
COMMENT ON COLUMN deployment_artifacts.checksum_sha256 IS
  'SHA-256 hex digest of the decoded artifact content, computed at upload time and re-verified on read.';
COMMENT ON COLUMN deployment_artifacts.retention_until IS
  'Auto-expiry date. Artifacts are pruned by the retention sweeper after this timestamp.';

CREATE INDEX IF NOT EXISTS idx_deployment_artifacts_deployment_id
  ON deployment_artifacts (deployment_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_deployment_artifacts_type
  ON deployment_artifacts (artifact_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_deployment_artifacts_retention
  ON deployment_artifacts (retention_until)
  WHERE retention_until < now();
