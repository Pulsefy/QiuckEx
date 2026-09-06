CREATE TABLE IF NOT EXISTS export_jobs (
  id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id              UUID         NOT NULL UNIQUE REFERENCES jobs (id) ON DELETE CASCADE,
  user_id             TEXT         NOT NULL,
  export_type         TEXT         NOT NULL
                                   CHECK (export_type IN ('transactions', 'links', 'payments')),
  format              TEXT         NOT NULL
                                   CHECK (format IN ('csv', 'json')),
  delivery_method     TEXT         NOT NULL
                                   CHECK (delivery_method IN ('webhook', 'email', 'download')),
  filters             JSONB        NOT NULL DEFAULT '{}'::jsonb,
  status              TEXT         NOT NULL DEFAULT 'queued'
                                   CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  delivery_reference  TEXT,
  failure_reason      TEXT,
  queued_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
  started_at          TIMESTAMPTZ,
  completed_at        TIMESTAMPTZ,
  failed_at           TIMESTAMPTZ,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_export_jobs_user_id
  ON export_jobs (user_id);

CREATE INDEX IF NOT EXISTS idx_export_jobs_status
  ON export_jobs (status);

COMMENT ON TABLE export_jobs IS
  'Export job records with status lifecycle (queued, running, completed, failed).';
