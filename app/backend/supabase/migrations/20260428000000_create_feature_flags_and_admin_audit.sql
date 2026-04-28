create table if not exists feature_flags (
  key text primary key,
  name text not null,
  description text not null default '',
  enabled boolean not null default false,
  kill_switch boolean not null default false,
  rollout_percentage integer not null default 0,
  allowed_users jsonb not null default '[]'::jsonb,
  environments jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default timezone('utc', now()),
  updated_by text not null default 'system',
  created_at timestamptz not null default timezone('utc', now())
);

create table if not exists admin_audit_logs (
  id uuid primary key,
  actor text not null,
  action text not null,
  target text,
  metadata jsonb not null default '{}'::jsonb,
  request_id text,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists admin_audit_logs_action_created_at_idx
  on admin_audit_logs (action, created_at desc);

create index if not exists admin_audit_logs_actor_created_at_idx
  on admin_audit_logs (actor, created_at desc);
