-- Migration to create branch preview environments table
CREATE TABLE IF NOT EXISTS branch_preview_environments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  branch_name TEXT NOT NULL UNIQUE,
  api_url TEXT NOT NULL,
  frontend_url TEXT NOT NULL,
  network TEXT NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  contract_registry_version TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_branch_name_active ON branch_preview_environments (branch_name, is_active);

-- Add to admin_audit_logs to track changes (table already exists)
-- This ensures our audit events are properly categorized
COMMENT ON TABLE branch_preview_environments IS 'Stores branch preview environment mappings for dynamic contributor previews';
COMMENT ON COLUMN branch_preview_environments.branch_name IS 'Normalized git branch name';
COMMENT ON COLUMN branch_preview_environments.expires_at IS 'Optional expiration timestamp for ephemeral previews';