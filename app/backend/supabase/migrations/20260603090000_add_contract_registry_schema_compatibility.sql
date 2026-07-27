alter table if exists public.contract_registry_entries
  add column if not exists schema_version text not null default '1.0.0',
  add column if not exists schema_compatibility jsonb not null default '{"min":"1.0.0","max":"1.0.0"}'::jsonb,
  add column if not exists init_params jsonb not null default '{}'::jsonb;

create index if not exists contract_registry_schema_version_idx
  on public.contract_registry_entries (network, contract_name, schema_version, is_active);
