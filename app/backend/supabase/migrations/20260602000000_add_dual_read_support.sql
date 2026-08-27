-- Add dual-read support columns to contract_registry_entries table
-- These columns enable safe contract ID transitions without data loss

alter table if exists public.contract_registry_entries
  add column if not exists previous_contract_id text,
  add column if not exists effective_ledger bigint,
  add column if not exists effective_time timestamptz;

-- Add check constraint to prevent invalid state:
-- if previous_contract_id exists, both effective_ledger and effective_time must be set
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'dual_read_window_constraint'
      AND conrelid = 'public.contract_registry_entries'::regclass
  ) THEN
    ALTER TABLE public.contract_registry_entries
      ADD CONSTRAINT dual_read_window_constraint
      CHECK (
        (previous_contract_id is null) or
        (previous_contract_id is not null and effective_ledger is not null)
      );
  END IF;
END
$$;

-- Add index for efficient dual-read queries
create index if not exists contract_registry_effective_ledger_idx
  on public.contract_registry_entries (network, contract_name, is_active, effective_ledger);
