-- BE-124: Scheduled reconciliation run history with drift alerting.
--
-- Persists a summary row for every scheduled/manual reconciliation run so
-- operators can inspect run history, per-run drift detail, and consecutive
-- failure streaks without digging through logs.

create table if not exists reconciliation_runs (
  run_id                  uuid        primary key,
  status                  text        not null check (status in ('success', 'drift', 'failed', 'skipped')),
  batch_size              integer,
  started_at              timestamptz not null,
  completed_at            timestamptz,
  duration_ms             bigint,

  escrows_processed       integer     not null default 0,
  escrows_irreconcilable  integer     not null default 0,
  payments_processed      integer     not null default 0,
  payments_irreconcilable integer     not null default 0,

  count_discrepancy       integer     not null default 0,
  amount_discrepancy      text        not null default '0',
  drift_exceeded          boolean     not null default false,

  alert_severity          text        check (alert_severity in ('warning', 'critical')),
  alert_message           text,
  failure_reason          text,
  skipped_reason          text,

  -- Per-record drift detail (irreconcilable / updated / skipped records),
  -- stored as JSON so the shape can evolve without a migration.
  drift_details           jsonb       not null default '[]'::jsonb,

  created_at              timestamptz not null default now()
);

-- Operator query indexes: newest runs first, by status, and single-run lookup.
create index if not exists idx_reconciliation_runs_started_at
  on reconciliation_runs (started_at desc);

create index if not exists idx_reconciliation_runs_status_started_at
  on reconciliation_runs (status, started_at desc);

-- Consecutive failure streak computation scans the newest runs first.
create index if not exists idx_reconciliation_runs_run_id
  on reconciliation_runs (run_id);