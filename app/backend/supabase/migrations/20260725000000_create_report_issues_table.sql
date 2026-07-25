-- BE-86: Report Issue Intake API — capture user-submitted bug reports and feedback
--
-- Stores structured issue reports from frontend/mobile with redacted sensitive data
-- and attachment references. Includes abuse prevention via IP-based rate limiting.
--
-- Privacy design:
--  • All user-provided content (description, context, reproduction) is redacted
--    before storage using the existing RedactionService
--  • IP addresses are never stored plaintext — only a SHA-256 hash for rate limiting
--  • Attachments are stored as metadata references only; actual files are stored separately
--  • Sensitive values (API keys, tokens, passwords) are automatically redacted

CREATE TABLE IF NOT EXISTS report_issues (
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- ── User identity (optional) ─────────────────────────────────────────────
  user_id           TEXT,                        -- Optional user ID for authenticated users

  -- ── Issue metadata ───────────────────────────────────────────────────────
  issue_type        TEXT        NOT NULL,       -- bug, feature_request, abuse_report, other
  title             TEXT        NOT NULL,
  description       TEXT        NOT NULL,

  -- ── Environment information ───────────────────────────────────────────────
  environment       JSONB       NOT NULL,       -- Platform, version, locale, etc.

  -- ── Reproduction and context (optional) ───────────────────────────────────
  reproduction      TEXT,                        -- Steps to reproduce
  context           JSONB,                       -- Additional context (redacted)
  attachments       JSONB,                       -- Attachment metadata references

  -- ── Redacted payload for storage ───────────────────────────────────────────
  redacted_payload  JSONB       NOT NULL,       -- Fully redacted submission data

  -- ── Privacy-safe identity for abuse prevention ────────────────────────────
  ip_address_hash   TEXT        NOT NULL,       -- SHA-256(request IP + salt)

  -- ── Lifecycle ─────────────────────────────────────────────────────────────
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  report_issues IS
  'User-submitted issue reports with redacted sensitive data and abuse prevention.';

COMMENT ON COLUMN report_issues.user_id IS
  'Optional user ID for authenticated users. Allows linking reports to user accounts.';

COMMENT ON COLUMN report_issues.issue_type IS
  'Type of issue: bug, feature_request, abuse_report, or other.';

COMMENT ON COLUMN report_issues.title IS
  'Brief title describing the issue.';

COMMENT ON COLUMN report_issues.description IS
  'Detailed description of the issue. Automatically redacted before storage.';

COMMENT ON COLUMN report_issues.environment IS
  'Environment information: platform, version, locale, timezone, screen dimensions.';

COMMENT ON COLUMN report_issues.reproduction IS
  'Steps to reproduce the issue. Automatically redacted before storage.';

COMMENT ON COLUMN report_issues.context IS
  'Additional context data (e.g., link IDs, transaction IDs). Automatically redacted.';

COMMENT ON COLUMN report_issues.attachments IS
  'Array of attachment metadata references (id, name, type, size, url). Files stored separately.';

COMMENT ON COLUMN report_issues.redacted_payload IS
  'Complete redacted submission payload for storage and analysis.';

COMMENT ON COLUMN report_issues.ip_address_hash IS
  'SHA-256(request IP + salt) for rate limiting and abuse prevention. Raw IP never persisted.';

-- ── Query indexes ─────────────────────────────────────────────────────────────
-- Find reports for a specific user.
CREATE INDEX IF NOT EXISTS idx_ri_user_id
  ON report_issues (user_id, created_at DESC)
  WHERE user_id IS NOT NULL;

-- Find recent reports for abuse detection (by IP hash).
CREATE INDEX IF NOT EXISTS idx_ri_ip_hash_created
  ON report_issues (ip_address_hash, created_at DESC);

-- Admin dashboard: surface recent reports first.
CREATE INDEX IF NOT EXISTS idx_ri_created_at
  ON report_issues (created_at DESC);

-- Filter by issue type for analytics.
CREATE INDEX IF NOT EXISTS idx_ri_issue_type
  ON report_issues (issue_type, created_at DESC);

-- Retention/cleanup support (if needed in future).
CREATE INDEX IF NOT EXISTS idx_ri_created_at_retention
  ON report_issues (created_at);
