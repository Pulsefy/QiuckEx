-- Migration: Create crash reporting tables
-- Description: Creates tables for crash reports and user settings with strict privacy controls

-- Table for crash reports
CREATE TABLE IF NOT EXISTS crash_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT,
  error JSONB NOT NULL,
  context JSONB,
  log_lines TEXT[] NOT NULL DEFAULT '{}',
  timestamp TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- Index for querying by user
  CONSTRAINT crash_reports_user_id_idx CHECK (user_id IS NULL OR length(user_id) > 0)
);

-- Index for efficient user queries
CREATE INDEX IF NOT EXISTS idx_crash_reports_user_id_timestamp 
  ON crash_reports(user_id, timestamp DESC) 
  WHERE user_id IS NOT NULL;

-- Index for cleanup queries
CREATE INDEX IF NOT EXISTS idx_crash_reports_timestamp 
  ON crash_reports(timestamp);

-- Table for user crash reporting settings
CREATE TABLE IF NOT EXISTS crash_reporting_settings (
  user_id TEXT PRIMARY KEY,
  crash_reporting_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  CONSTRAINT crash_reporting_settings_user_id_check CHECK (length(user_id) > 0)
);

-- Row Level Security (RLS) policies
-- Enable RLS on both tables
ALTER TABLE crash_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE crash_reporting_settings ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only read their own crash reports
CREATE POLICY crash_reports_user_read ON crash_reports
  FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true));

-- Policy: Service role can insert crash reports
CREATE POLICY crash_reports_service_insert ON crash_reports
  FOR INSERT
  WITH CHECK (true);

-- Policy: Users can read their own settings
CREATE POLICY crash_reporting_settings_user_read ON crash_reporting_settings
  FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true));

-- Policy: Users can update their own settings
CREATE POLICY crash_reporting_settings_user_update ON crash_reporting_settings
  FOR UPDATE
  USING (user_id = current_setting('app.current_user_id', true));

-- Policy: Users can insert their own settings
CREATE POLICY crash_reporting_settings_user_insert ON crash_reporting_settings
  FOR INSERT
  WITH CHECK (user_id = current_setting('app.current_user_id', true));

-- Comments for documentation
COMMENT ON TABLE crash_reports IS 'Stores crash reports with redacted logs and error information';
COMMENT ON TABLE crash_reporting_settings IS 'Stores user preferences for crash reporting opt-in/out';
COMMENT ON COLUMN crash_reports.error IS 'Redacted error information (name, message, stack)';
COMMENT ON COLUMN crash_reports.context IS 'Redacted context information about the crash';
COMMENT ON COLUMN crash_reports.log_lines IS 'Redacted log lines captured before the crash';
COMMENT ON COLUMN crash_reporting_settings.crash_reporting_enabled IS 'Whether the user has opted in to crash reporting';
