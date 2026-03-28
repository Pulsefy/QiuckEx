-- =============================================================================
-- Recurring Payment Links Engine Tables
-- =============================================================================
-- Support for subscription-style payment links with automated execution
-- =============================================================================

-- ---------------------------------------------------------------------------
-- recurring_payment_links
-- ---------------------------------------------------------------------------
-- Stores metadata for recurring payment links (subscriptions)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS recurring_payment_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Link identification
  username TEXT,  -- Optional: quickex.to/username route
  destination TEXT,  -- Optional: direct Stellar public key (G...)
  
  -- Payment details
  amount DECIMAL(17,7) NOT NULL,
  asset TEXT NOT NULL,  -- Asset code (XLM, USDC, etc.)
  asset_issuer TEXT,  -- Issuer address for non-native assets
  
  -- Recurring schedule
  frequency TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly', 'yearly')),
  start_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  end_date TIMESTAMPTZ,  -- Null for indefinite recurring payments
  total_periods INTEGER,  -- Total number of payments (null for indefinite)
  
  -- Execution tracking
  executed_count INTEGER NOT NULL DEFAULT 0,
  next_execution_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Status management
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed', 'cancelled')),
  
  -- Optional metadata
  memo TEXT,
  memo_type TEXT DEFAULT 'text' CHECK (memo_type IN ('text', 'id', 'hash', 'return')),
  reference_id TEXT,
  privacy_enabled BOOLEAN DEFAULT false,
  
  -- Timestamps
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Constraints
  CONSTRAINT recurring_links_amount_positive CHECK (amount > 0),
  CONSTRAINT recurring_links_either_username_or_destination 
    CHECK (username IS NOT NULL OR destination IS NOT NULL),
  CONSTRAINT recurring_links_start_before_end 
    CHECK (end_date IS NULL OR end_date > start_date),
  CONSTRAINT recurring_links_total_periods_positive 
    CHECK (total_periods IS NULL OR total_periods > 0),
  CONSTRAINT recurring_links_executed_within_total 
    CHECK (total_periods IS NULL OR executed_count <= total_periods)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS recurring_links_username_idx ON recurring_payment_links (username);
CREATE INDEX IF NOT EXISTS recurring_links_destination_idx ON recurring_payment_links (destination);
CREATE INDEX IF NOT EXISTS recurring_links_status_idx ON recurring_payment_links (status);
CREATE INDEX IF NOT EXISTS recurring_links_next_execution_idx ON recurring_payment_links (next_execution_date);
CREATE INDEX IF NOT EXISTS recurring_links_frequency_idx ON recurring_payment_links (frequency);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_recurring_link_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER recurring_payment_links_updated_at_trigger
  BEFORE UPDATE ON recurring_payment_links
  FOR EACH ROW
  EXECUTE FUNCTION update_recurring_link_updated_at();

COMMENT ON TABLE recurring_payment_links IS 'Recurring payment link configurations (subscriptions)';
COMMENT ON COLUMN recurring_payment_links.username IS 'Optional username route (quickex.to/username)';
COMMENT ON COLUMN recurring_payment_links.destination IS 'Optional Stellar public key for direct routing';
COMMENT ON COLUMN recurring_payment_links.frequency IS 'Payment frequency: daily, weekly, monthly, yearly';
COMMENT ON COLUMN recurring_payment_links.status IS 'Link status: active, paused, completed, cancelled';
COMMENT ON COLUMN recurring_payment_links.next_execution_date IS 'Next scheduled payment execution date';

-- ---------------------------------------------------------------------------
-- recurring_payment_executions
-- ---------------------------------------------------------------------------
-- Tracks individual payment executions for each recurring link
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS recurring_payment_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Foreign key to recurring link
  recurring_link_id UUID NOT NULL REFERENCES recurring_payment_links(id) ON DELETE CASCADE,
  
  -- Period information
  period_number INTEGER NOT NULL,
  
  -- Schedule and execution timing
  scheduled_at TIMESTAMPTZ NOT NULL,
  executed_at TIMESTAMPTZ,
  
  -- Payment details
  amount DECIMAL(17,7) NOT NULL,
  asset TEXT NOT NULL,
  
  -- Execution status
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'success', 'failed', 'skipped')),
  
  -- Transaction details
  transaction_hash TEXT,
  stellar_operation_id TEXT,
  
  -- Failure handling
  failure_reason TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  last_retry_at TIMESTAMPTZ,
  
  -- Notification tracking
  notification_sent BOOLEAN DEFAULT false,
  notification_sent_at TIMESTAMPTZ,
  
  -- Timestamps
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Constraints
  CONSTRAINT recurring_executions_period_positive CHECK (period_number > 0),
  CONSTRAINT recurring_executions_retry_non_negative CHECK (retry_count >= 0),
  UNIQUE (recurring_link_id, period_number)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS recurring_executions_link_id_idx ON recurring_payment_executions (recurring_link_id);
CREATE INDEX IF NOT EXISTS recurring_executions_status_idx ON recurring_payment_executions (status);
CREATE INDEX IF NOT EXISTS recurring_executions_scheduled_at_idx ON recurring_payment_executions (scheduled_at);
CREATE INDEX IF NOT EXISTS recurring_executions_transaction_hash_idx ON recurring_payment_executions (transaction_hash);

-- Composite index for scheduler queries
CREATE INDEX IF NOT EXISTS recurring_executions_pending_schedule_idx 
  ON recurring_payment_executions (status, scheduled_at) 
  WHERE status = 'pending';

COMMENT ON TABLE recurring_payment_executions IS 'Individual payment execution records for recurring links';
COMMENT ON COLUMN recurring_payment_executions.period_number IS 'Sequential period number (1, 2, 3, ...)';
COMMENT ON COLUMN recurring_payment_executions.scheduled_at IS 'When this payment was scheduled to execute';
COMMENT ON COLUMN recurring_payment_executions.executed_at IS 'When this payment was actually executed';
COMMENT ON COLUMN recurring_payment_executions.status IS 'Execution status: pending, success, failed, skipped';
COMMENT ON COLUMN recurring_payment_executions.retry_count IS 'Number of retry attempts made';

-- ---------------------------------------------------------------------------
-- Helper functions
-- ---------------------------------------------------------------------------

-- Function to calculate next execution date based on frequency
CREATE OR REPLACE FUNCTION calculate_next_execution_date(
  current_date TIMESTAMPTZ,
  freq TEXT
)
RETURNS TIMESTAMPTZ AS $$
BEGIN
  CASE freq
    WHEN 'daily' THEN
      RETURN current_date + INTERVAL '1 day';
    WHEN 'weekly' THEN
      RETURN current_date + INTERVAL '1 week';
    WHEN 'monthly' THEN
      RETURN current_date + INTERVAL '1 month';
    WHEN 'yearly' THEN
      RETURN current_date + INTERVAL '1 year';
    ELSE
      RETURN current_date;
  END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to check if a recurring link should execute
CREATE OR REPLACE FUNCTION should_execute_recurring_link(
  link_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
  link_record RECORD;
BEGIN
  SELECT * INTO link_record
  FROM recurring_payment_links
  WHERE id = link_id;
  
  -- Check if link exists
  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;
  
  -- Check status
  IF link_record.status != 'active' THEN
    RETURN FALSE;
  END IF;
  
  -- Check if we've reached the total periods
  IF link_record.total_periods IS NOT NULL 
     AND link_record.executed_count >= link_record.total_periods THEN
    RETURN FALSE;
  END IF;
  
  -- Check if end_date has passed
  IF link_record.end_date IS NOT NULL 
     AND now() > link_record.end_date THEN
    RETURN FALSE;
  END IF;
  
  -- Check if it's time to execute
  IF now() < link_record.next_execution_date THEN
    RETURN FALSE;
  END IF;
  
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION calculate_next_execution_date IS 'Calculates next execution date based on frequency';
COMMENT ON FUNCTION should_execute_recurring_link IS 'Determines if a recurring link should execute now';
