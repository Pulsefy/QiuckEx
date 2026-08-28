-- Migration: Create teams and team_members tables for team management (Issue #62)

-- Teams table
CREATE TABLE IF NOT EXISTS teams (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 64),
  owner_id    TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_teams_owner_id ON teams (owner_id);

-- Team members table
CREATE TABLE IF NOT EXISTS team_members (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  name            TEXT,
  role            TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('active', 'pending')),
  joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at  TIMESTAMPTZ,
  invited_by      TEXT,
  UNIQUE (team_id, user_id),
  UNIQUE (team_id, email)
);

CREATE INDEX IF NOT EXISTS idx_team_members_team_id     ON team_members (team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id     ON team_members (user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_email       ON team_members (email);

-- Team invites table (for invite links with 7-day expiry)
CREATE TABLE IF NOT EXISTS team_invites (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  token       TEXT NOT NULL UNIQUE,
  role        TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
  created_by  TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_team_invites_team_id    ON team_invites (team_id);
CREATE INDEX IF NOT EXISTS idx_team_invites_token      ON team_invites (token);
CREATE INDEX IF NOT EXISTS idx_team_invites_expires_at ON team_invites (expires_at);

-- Trigger to keep teams.updated_at current
CREATE OR REPLACE FUNCTION update_teams_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_teams_updated_at ON teams;
CREATE TRIGGER trg_teams_updated_at
  BEFORE UPDATE ON teams
  FOR EACH ROW
  EXECUTE FUNCTION update_teams_updated_at();
