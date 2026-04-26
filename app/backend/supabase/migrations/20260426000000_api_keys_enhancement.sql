-- =============================================================================
-- API Keys Enhancement: Rotation Overlap and Monthly Quotas
-- =============================================================================

-- Add columns for rotation overlap and quota tracking
ALTER TABLE api_keys
ADD COLUMN IF NOT EXISTS key_hash_old   TEXT,
ADD COLUMN IF NOT EXISTS rotated_at     TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS last_reset_at   TIMESTAMPTZ DEFAULT now();

-- Update increment_api_key_usage to handle monthly resets
CREATE OR REPLACE FUNCTION increment_api_key_usage(key_id UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    current_reset TIMESTAMPTZ;
BEGIN
    SELECT last_reset_at INTO current_reset FROM api_keys WHERE id = key_id;

    -- If current month is different from last_reset_at month, reset count
    IF date_trunc('month', now()) > date_trunc('month', current_reset) THEN
        UPDATE api_keys
        SET
            request_count = 1,
            last_reset_at = now(),
            last_used_at  = now(),
            updated_at    = now()
        WHERE id = key_id AND is_active = true;
    ELSE
        UPDATE api_keys
        SET
            request_count = request_count + 1,
            last_used_at  = now(),
            updated_at    = now()
        WHERE id = key_id AND is_active = true;
    END IF;
END;
$$;
