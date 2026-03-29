-- =============================================================================
-- Add 'telegram' to notification_preferences channel enum
-- =============================================================================

-- Update the CHECK constraint on notification_preferences to include 'telegram'
-- Note: We need to drop and recreate the constraint because PostgreSQL doesn't 
-- support altering CHECK constraints directly

-- Drop the existing constraint
ALTER TABLE notification_preferences
DROP CONSTRAINT IF EXISTS notification_preferences_channel_check;

-- Add the updated constraint with 'telegram' included
ALTER TABLE notification_preferences
ADD CONSTRAINT notification_preferences_channel_check
CHECK (channel IN ('email', 'push', 'webhook', 'telegram'));

-- Add comment to document the change
COMMENT ON COLUMN notification_preferences.channel IS 
  'Notification channel: email, push, webhook, or telegram';
