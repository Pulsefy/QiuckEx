-- BE-31: Network Safety Gate
-- Seeds the three high-risk feature flags that gate mainnet write flows.
-- Safe defaults: enabled=false so mainnet actions are blocked until an admin
-- explicitly enables them via PATCH /admin/feature-flags/:key.

INSERT INTO feature_flags (key, name, description, enabled, kill_switch, rollout_percentage, allowed_users, environments, metadata, updated_by)
VALUES
  (
    'mainnet.refunds',
    'Mainnet Refunds',
    'Allows refund initiation on mainnet. Disabled by default; must be explicitly enabled by an admin.',
    false, false, 0, '[]'::jsonb, '["production"]'::jsonb,
    '{"highRisk": true, "flow": "refunds"}'::jsonb,
    'system'
  ),
  (
    'mainnet.dispute_actions',
    'Mainnet Dispute Actions',
    'Allows escrow dispute actions on mainnet. Disabled by default.',
    false, false, 0, '[]'::jsonb, '["production"]'::jsonb,
    '{"highRisk": true, "flow": "dispute_actions"}'::jsonb,
    'system'
  ),
  (
    'mainnet.contract_writes',
    'Mainnet Contract Writes',
    'Allows Soroban contract write operations on mainnet. Disabled by default.',
    false, false, 0, '[]'::jsonb, '["production"]'::jsonb,
    '{"highRisk": true, "flow": "contract_writes"}'::jsonb,
    'system'
  )
ON CONFLICT (key) DO NOTHING;
