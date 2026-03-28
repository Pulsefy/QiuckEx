-- Enable pg_trgm extension for advanced fuzzy search (if not already enabled)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Create a SQL function for fuzzy username search with trigram similarity
-- This provides fast, accurate search results ranked by relevance
CREATE OR REPLACE FUNCTION search_usernames(search_query TEXT, result_limit INTEGER DEFAULT 10)
RETURNS TABLE (
  id UUID,
  username TEXT,
  public_key TEXT,
  created_at TIMESTAMPTZ,
  last_active_at TIMESTAMPTZ,
  is_public BOOLEAN,
  similarity_score NUMERIC
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id,
    u.username,
    u.public_key,
    u.created_at,
    u.last_active_at,
    u.is_public,
    -- Calculate similarity score using word_similarity (0-1 scale, convert to 0-100)
    ROUND(word_similarity(search_query, u.username) * 100)::NUMERIC AS similarity_score
  FROM usernames u
  WHERE u.is_public = TRUE
    AND word_similarity(search_query, u.username) > 0.3 -- Minimum similarity threshold
  ORDER BY 
    similarity_score DESC,
    u.last_active_at DESC
  LIMIT result_limit;
END;
$$ LANGUAGE plpgsql STABLE;

-- Add index to optimize trigram searches (required for word_similarity performance)
CREATE INDEX IF NOT EXISTS usernames_username_trgm_idx ON usernames USING gin (username gin_trgm_ops);

COMMENT ON FUNCTION search_usernames IS 'Fuzzy search for public usernames using trigram similarity';
