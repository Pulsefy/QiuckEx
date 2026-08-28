-- Supports GET /marketplace sort=price_asc|price_desc, filtered to
-- status = 'active', with (id) as the deterministic pagination tiebreaker.
CREATE INDEX IF NOT EXISTS username_marketplace_active_price_idx
  ON username_marketplace (status, asking_price, id);

-- Supports GET /marketplace sort=newest|ending_soon (created_at is used
-- for both, since ends_at is a fixed 48h offset from created_at).
CREATE INDEX IF NOT EXISTS username_marketplace_active_created_idx
  ON username_marketplace (status, created_at, id);
