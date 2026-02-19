-- Usernames table for quickex.to/yourname
-- Uniqueness is enforced at the database to avoid race conditions on concurrent creation.

CREATE TABLE IF NOT EXISTS usernames (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Uniqueness: store normalized (lowercase) username and enforce unique constraint.
  CONSTRAINT usernames_username_unique UNIQUE (username)
);

-- Index for listing usernames by wallet (public_key).
CREATE INDEX IF NOT EXISTS usernames_public_key_idx ON usernames (public_key);

-- Optional: enforce lowercase at DB level so no client can bypass normalization.
ALTER TABLE usernames
  ADD CONSTRAINT usernames_username_lowercase
  CHECK (username = lower(username));

COMMENT ON TABLE usernames IS 'Registered usernames (quickex.to/yourname). Username is stored normalized (lowercase).';
COMMENT ON COLUMN usernames.username IS 'Normalized username (lowercase, 3-32 chars, [a-z0-9_]).';
COMMENT ON COLUMN usernames.public_key IS 'Stellar public key (G...) of the owner.';
