-- Create verified_assets table for asset registry (BE-07)
--
-- Stores verified assets (XLM, USDC, etc.) plus metadata used by link generators and path payments.

CREATE TABLE IF NOT EXISTS verified_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code VARCHAR(12) NOT NULL,
  issuer VARCHAR(56), -- NULL for XLM (native)
  type VARCHAR(20) NOT NULL, -- 'native' | 'credit_alphanum4' | 'credit_alphanum12'
  decimals INTEGER NOT NULL DEFAULT 7,
  icon_url TEXT,
  verified BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Index for searching and listing
CREATE INDEX IF NOT EXISTS idx_verified_assets_code ON verified_assets(code);
CREATE INDEX IF NOT EXISTS idx_verified_assets_verified ON verified_assets(verified);

-- Custom unique constraints:
-- 1. Only one native asset (XLM) where issuer is null
CREATE UNIQUE INDEX IF NOT EXISTS idx_verified_assets_native_uniq ON verified_assets (code) WHERE issuer IS NULL;
-- 2. Non-native assets must have unique code and issuer pairs
CREATE UNIQUE INDEX IF NOT EXISTS idx_verified_assets_code_issuer_uniq ON verified_assets (code, issuer) WHERE issuer IS NOT NULL;

-- Seed initial verified assets
INSERT INTO verified_assets (code, issuer, type, decimals, icon_url, verified)
VALUES
  ('XLM', NULL, 'native', 7, 'https://assets.stellar.org/images/logos/xlm-icon.svg', true)
ON CONFLICT (code) WHERE issuer IS NULL DO NOTHING;

INSERT INTO verified_assets (code, issuer, type, decimals, icon_url, verified)
VALUES
  ('USDC', 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN', 'credit_alphanum4', 7, 'https://www.circle.com/usdc-icon', true),
  ('AQUA', 'GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA', 'credit_alphanum4', 7, NULL, true),
  ('yXLM', 'GARDNV3Q7YGT4AKSDF25LT32YSCCW4EV22Y2TV3I2PU2MMXJTEDL5T55', 'credit_alphanum4', 7, NULL, true)
ON CONFLICT (code, issuer) WHERE issuer IS NOT NULL DO NOTHING;
