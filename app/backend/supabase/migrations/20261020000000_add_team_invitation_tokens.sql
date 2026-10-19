alter table public.team_members
  add column if not exists invite_token_hash text,
  add column if not exists invite_expires_at timestamptz;

create unique index if not exists team_members_invite_token_hash_idx
  on public.team_members (invite_token_hash)
  where invite_token_hash is not null;