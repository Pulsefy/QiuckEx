create table if not exists public.team_members (
  id uuid primary key default gen_random_uuid(),
  organization_id text not null,
  name text not null check (length(trim(name)) between 1 and 120),
  email text not null check (length(trim(email)) between 3 and 320),
  role text not null default 'viewer' check (role in ('admin', 'operator', 'viewer')),
  status text not null default 'pending' check (status in ('active', 'pending')),
  invited_by text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists team_members_organization_idx
  on public.team_members (organization_id, created_at);

create unique index if not exists team_members_organization_email_idx
  on public.team_members (organization_id, lower(email));

comment on table public.team_members is
  'QuickEx organization team membership; access is enforced by the API key organization scope.';
