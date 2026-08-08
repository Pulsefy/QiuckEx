-- Create contract spec table
create table if not exists public.contract_spec_entries (
  id uuid primary key default gen_random_uuid(),
  contract_name text not null,
  network text not null,
  contract_id text not null,
  wasm_hash text not null,
  contract_version integer not null,
  schema_version text not null default '1.0.0',
  methods jsonb not null default '[]'::jsonb,
  events jsonb not null default '[]'::jsonb,
  storage jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  version bigint not null,
  updated_at timestamptz not null default timezone('utc', now()),
  created_at timestamptz not null default timezone('utc', now())
);

-- Create indexes for efficient queries
create index if not exists contract_spec_entries_network_idx
  on public.contract_spec_entries (network, contract_name);

create index if not exists contract_spec_entries_version_idx
  on public.contract_spec_entries (network, contract_name, version desc);

create unique index if not exists contract_spec_entries_version_key
  on public.contract_spec_entries (network, contract_name, version);

-- Add comment for documentation
comment on table public.contract_spec_entries is 'Stores contract ABI/specification for frontend introspection';
comment on column public.contract_spec_entries.methods is 'Array of contract methods with signatures, args, return types, and access control';
comment on column public.contract_spec_entries.events is 'Array of contract events with fields and descriptions';
comment on column public.contract_spec_entries.storage is 'Array of storage structures with fields and descriptions';