-- Migration: Create branch_deployments table
-- Description: Syncs deployment metadata from GitHub branches/PRs into the backend.

CREATE TABLE IF NOT EXISTS public.branch_deployments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  branch_name TEXT UNIQUE NOT NULL,
  pr_number INTEGER,
  commit_sha TEXT NOT NULL,
  preview_url TEXT,
  status TEXT NOT NULL,
  event_timestamp TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS branch_deployments_pr_number_idx ON public.branch_deployments(pr_number);
