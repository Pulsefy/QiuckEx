create table if not exists public.contract_registry_entries (
  id uuid primary key default gen_random_uuid(),
  contract_name text not null,
  network text not null,
  contract_id text not null,
  wasm_hash text not null,
  contract_version integer not null default 1,
  deployment_id text,
  metadata jsonb not null default '{}'::jsonb,
  published_by text not null,
  version bigint not null,
  network_passphrase text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists contract_registry_entries_network_idx
  on public.contract_registry_entries (network, contract_name, is_active);

create unique index if not exists contract_registry_entries_version_key
  on public.contract_registry_entries (network, contract_name, version);
