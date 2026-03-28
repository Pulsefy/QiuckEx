-- Add visibility and activity tracking to usernames table
-- Enables public profile discovery and trending creators features

-- Add is_public column (defaults to false for backward compatibility)
ALTER TABLE usernames
ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT false;

-- Add last_active_at timestamp for tracking user activity
ALTER TABLE usernames
ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ DEFAULT now();

-- Create index for fast public profile searches
CREATE INDEX IF NOT EXISTS usernames_is_public_idx ON usernames (is_public) WHERE is_public = true;

-- Create index for activity-based queries (trending)
CREATE INDEX IF NOT EXISTS usernames_last_active_at_idx ON usernames (last_active_at DESC);

-- Create composite index for public profiles sorted by activity
CREATE INDEX IF NOT EXISTS usernames_public_active_idx ON usernames (is_public, last_active_at DESC) WHERE is_public = true;

-- Add comment documenting the new columns
COMMENT ON COLUMN usernames.is_public IS 'Whether this profile is visible in public search and trending';
COMMENT ON COLUMN usernames.last_active_at IS 'Last activity timestamp for trending calculations';
