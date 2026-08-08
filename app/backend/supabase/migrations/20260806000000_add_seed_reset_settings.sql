-- Create seed reset settings table
create table if not exists public.seed_reset_settings (
  id uuid primary key default gen_random_uuid(),
  enabled boolean not null default true,
  interval text not null default '0 0 * * *',
  exclusions text[] not null default '{}',
  max_retries integer not null default 3,
  retry_on_failure boolean not null default true,
  last_reset_time timestamptz,
  total_resets integer not null default 0,
  successful_resets integer not null default 0,
  failed_resets integer not null default 0,
  updated_at timestamptz not null default timezone('utc', now()),
  created_at timestamptz not null default timezone('utc', now())
);

-- Create seed reset history table for audit
create table if not exists public.seed_reset_history (
  id uuid primary key default gen_random_uuid(),
  triggered_by text not null,
  trigger_type text not null check (trigger_type in ('scheduled', 'manual', 'retry', 'force')),
  success boolean not null,
  seeded_links integer not null default 0,
  seeded_transactions integer not null default 0,
  skipped_links integer not null default 0,
  skipped_transactions integer not null default 0,
  errors text[] not null default '{}',
  exclusions_applied text[] not null default '{}',
  retry_count integer not null default 0,
  execution_time_ms integer,
  created_at timestamptz not null default timezone('utc', now())
);

-- Create indexes
create index if not exists seed_reset_history_created_at_idx
  on public.seed_reset_history (created_at desc);

create index if not exists seed_reset_history_trigger_type_idx
  on public.seed_reset_history (trigger_type);

create index if not exists seed_reset_history_success_idx
  on public.seed_reset_history (success);

-- Add comments for documentation
comment on table public.seed_reset_settings is 'Configuration settings for automated seed reset scheduler';
comment on table public.seed_reset_history is 'Audit log for all seed reset operations';
comment on column public.seed_reset_history.triggered_by is 'Who or what triggered the reset (API key ID or system)';
comment on column public.seed_reset_history.trigger_type is 'Type of trigger: scheduled, manual, retry, or force';