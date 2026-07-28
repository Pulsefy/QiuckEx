-- Branch preview environments + auto-expiry metadata (BE-90)

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

ALTER TABLE branch_preview_environments
  ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS is_shared BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS expiry_exempt BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS auto_expired_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS auto_expiry_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_branch_preview_active_expiry
  ON branch_preview_environments (is_active, expiry_exempt, is_shared);

CREATE TABLE IF NOT EXISTS branch_preview_expiry_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  preview_id UUID NOT NULL REFERENCES branch_preview_environments(id) ON DELETE CASCADE,
  branch_name TEXT NOT NULL,
  expiry_reason TEXT NOT NULL,
  previous_is_active BOOLEAN NOT NULL,
  last_activity_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_by TEXT NOT NULL,
  run_id TEXT NOT NULL,
  note TEXT
);

CREATE INDEX IF NOT EXISTS idx_branch_preview_expiry_audit_processed
  ON branch_preview_expiry_audit (processed_at DESC);

COMMENT ON COLUMN branch_preview_environments.is_shared IS 'Shared/long-lived preview mapping; skipped by auto-expiry worker';
COMMENT ON COLUMN branch_preview_environments.expiry_exempt IS 'Explicit exemption from scheduled preview auto-expiry';
