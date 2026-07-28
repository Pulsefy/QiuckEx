-- Add featured status to usernames table
-- Enables curated "featured" username discovery alongside trending/recently-active

ALTER TABLE usernames
ADD COLUMN IF NOT EXISTS is_featured BOOLEAN NOT NULL DEFAULT false;

-- Manual ordering for featured profiles (lower = higher priority). NULL sorts last.
ALTER TABLE usernames
ADD COLUMN IF NOT EXISTS featured_rank INTEGER;

-- Composite index for featured discovery lookups, ordered by rank then id (tiebreaker)
CREATE INDEX IF NOT EXISTS usernames_featured_idx
  ON usernames (is_featured, featured_rank, id)
  WHERE is_featured = true AND is_public = true;

COMMENT ON COLUMN usernames.is_featured IS 'Whether this profile is curated/featured for discovery';
COMMENT ON COLUMN usernames.featured_rank IS 'Manual ordering for featured profiles (lower = higher priority); NULL sorts last';
