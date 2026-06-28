-- Contributor Preview Data Isolation — BE-59
--
-- Adds preview scope tracking and filtering across all data tables so that
-- preview-environments only surface their own scoped test data and cannot leak
-- into the shared testnet namespace.

-- ─── preview_scopes ───────────────────────────────────────────────────────────
-- Registry of active preview scopes.  Each scope has a short TTL after which
-- the cleanup job deletes its associated records.

CREATE TABLE IF NOT EXISTS preview_scopes (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Stable identifier that appears in the `X-Preview-Scope` header
  -- (e.g. "pr-42" or "feat-be-preview-data-isolation").
  scope_id        TEXT        NOT NULL UNIQUE,

  -- Human-friendly metadata for the dashboard / admin UI.
  branch_name     TEXT        NOT NULL,
  github_pr_url   TEXT,
  owner_public_key TEXT,      -- Stellar public key that created this scope

  -- Records created under this scope live until this timestamp.
  expires_at      TIMESTAMPTZ NOT NULL,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_preview_scopes_expires_at
  ON preview_scopes (expires_at)
  WHERE expires_at > NOW();

-- Auto-maintain updated_at.
CREATE OR REPLACE FUNCTION trigger_preview_scopes_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER preview_scopes_updated_at
  BEFORE UPDATE ON preview_scopes
  FOR EACH ROW EXECUTE FUNCTION trigger_preview_scopes_set_updated_at();

COMMENT ON TABLE  preview_scopes         IS 'Active preview branch/workspace scopes with TTL';
COMMENT ON COLUMN preview_scopes.scope_id IS 'Unique scope identifier sent via X-Preview-Scope header';


-- ─── Add preview_scope columns to all scoped tables ──────────────────────────

-- payment_links
ALTER TABLE payment_links
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_payment_links_preview_scope
  ON payment_links (preview_scope)
  WHERE preview_scope IS NOT NULL;

-- recurring_payment_links
ALTER TABLE recurring_payment_links
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_recurring_links_preview_scope
  ON recurring_payment_links (preview_scope)
  WHERE preview_scope IS NOT NULL;

-- recurring_payment_executions
ALTER TABLE recurring_payment_executions
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_recurring_executions_preview_scope
  ON recurring_payment_executions (preview_scope)
  WHERE preview_scope IS NOT NULL;

-- in_app_notifications
ALTER TABLE in_app_notifications
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_in_app_notifications_preview_scope
  ON in_app_notifications (preview_scope)
  WHERE preview_scope IS NOT NULL;

-- notification_log
ALTER TABLE notification_log
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_notification_log_preview_scope
  ON notification_log (preview_scope)
  WHERE preview_scope IS NOT NULL;

-- transaction_receipts
ALTER TABLE transaction_receipts
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_tx_receipts_preview_scope
  ON transaction_receipts (preview_scope)
  WHERE preview_scope IS NOT NULL;

-- unmatched_transactions
ALTER TABLE unmatched_transactions
  ADD COLUMN IF NOT EXISTS preview_scope TEXT;

CREATE INDEX IF NOT EXISTS idx_unmatched_tx_preview_scope
  ON unmatched_transactions (preview_scope)
  WHERE preview_scope IS NOT NULL;


-- ─── Helper: scope-aware RLS-friendly filtering ─────────────────────────────
-- The backend enforces scope filtering in application code (see preview-scope
-- module).  This helper is used by the cleanup job.

CREATE OR REPLACE FUNCTION delete_expired_preview_scope_data(
  p_scope_id TEXT
)
RETURNS TABLE (deleted_from TEXT, row_count BIGINT) AS $$
DECLARE
  cnt BIGINT;
BEGIN
  -- payment_links
  DELETE FROM payment_links WHERE preview_scope = p_scope_id;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  IF cnt > 0 THEN RETURN QUERY SELECT 'payment_links'::TEXT, cnt; END IF;

  -- recurring_payment_links (cascades to executions)
  DELETE FROM recurring_payment_links WHERE preview_scope = p_scope_id;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  IF cnt > 0 THEN RETURN QUERY SELECT 'recurring_payment_links'::TEXT, cnt; END IF;

  -- in_app_notifications
  DELETE FROM in_app_notifications WHERE preview_scope = p_scope_id;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  IF cnt > 0 THEN RETURN QUERY SELECT 'in_app_notifications'::TEXT, cnt; END IF;

  -- notification_log
  DELETE FROM notification_log WHERE preview_scope = p_scope_id;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  IF cnt > 0 THEN RETURN QUERY SELECT 'notification_log'::TEXT, cnt; END IF;

  -- transaction_receipts
  DELETE FROM transaction_receipts WHERE preview_scope = p_scope_id;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  IF cnt > 0 THEN RETURN QUERY SELECT 'transaction_receipts'::TEXT, cnt; END IF;

  -- unmatched_transactions
  DELETE FROM unmatched_transactions WHERE preview_scope = p_scope_id;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  IF cnt > 0 THEN RETURN QUERY SELECT 'unmatched_transactions'::TEXT, cnt; END IF;
END;
$$ LANGUAGE plpgsql;
