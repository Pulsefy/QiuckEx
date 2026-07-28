-- Create job_replay_log table for tracking manual replays of dead-letter queue jobs
-- This table maintains an audit trail of all manual replay operations

create table if not exists job_replay_log (
  id uuid default gen_random_uuid() primary key,
  job_id uuid not null references jobs(id) on delete cascade,
  job_type text not null,
  status text not null check (status in ('queued', 'succeeded', 'failed', 'rejected')),
  reason text,
  triggered_by text not null default 'api',
  previous_attempts integer not null,
  created_at timestamptz default now() not null
);

-- Add indexes for efficient querying
create index if not exists idx_job_replay_log_job_id on job_replay_log(job_id);
create index if not exists idx_job_replay_log_created_at on job_replay_log(created_at);
create index if not exists idx_job_replay_log_job_type on job_replay_log(job_type);
create index if not exists idx_job_replay_log_status on job_replay_log(status);