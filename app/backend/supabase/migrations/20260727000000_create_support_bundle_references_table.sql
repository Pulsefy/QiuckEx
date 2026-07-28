-- BE-94: Support Bundle Upload Reference API
--
-- Links a client-generated support bundle id to an issue report or a receipt,
-- so support staff can locate diagnostics for a ticket without the client
-- re-uploading them. The raw bundle content is never stored here — only a
-- pointer plus lifecycle metadata. References auto-expire and are redacted
-- after their retention window (default 30 days, max 90).

CREATE TABLE IF NOT EXISTS support_bundle_references (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  bundle_id     TEXT        NOT NULL,
  target_type   TEXT        NOT NULL CHECK (target_type IN ('issue_report', 'receipt')),
  target_id     TEXT        NOT NULL,

  created_by    TEXT        NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,

  redacted      BOOLEAN     NOT NULL DEFAULT FALSE,
  redacted_at   TIMESTAMPTZ,

  CONSTRAINT support_bundle_references_unique_link
    UNIQUE (bundle_id, target_type, target_id)
);

COMMENT ON TABLE support_bundle_references IS
  'Links support bundle ids to issue reports or receipts. Bundle content itself lives elsewhere; this is a pointer with lifecycle/redaction metadata.';
COMMENT ON COLUMN support_bundle_references.bundle_id IS
  'Client-supplied support bundle identifier. Never returned unredacted by the API.';
COMMENT ON COLUMN support_bundle_references.expires_at IS
  'Auto-expiry timestamp. The retention sweeper redacts references past this date.';
COMMENT ON COLUMN support_bundle_references.redacted IS
  'True once the reference has expired or been manually redacted; lookups exclude these.';

-- Lookup references attached to a given issue report or receipt.
CREATE INDEX IF NOT EXISTS idx_support_bundle_references_target
  ON support_bundle_references (target_type, target_id, created_at DESC);

-- Retention sweeper.
CREATE INDEX IF NOT EXISTS idx_support_bundle_references_expiry
  ON support_bundle_references (expires_at)
  WHERE redacted = FALSE;
