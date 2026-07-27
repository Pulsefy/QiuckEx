-- BE-PP: Payment page abuse signals — capture scraping, brute-force, replay.
--
-- Stores privacy-safe signals from public payment page endpoints so operators
-- can detect suspicious patterns (rapid-fire retries, unknown user-agents,
-- geo-anomalies) before they cause outages or financial loss.
--
-- Privacy design:
--  • IP addresses are never stored plaintext — only a SHA-256 hash and a
--    /24 prefix for coarse network-level grouping are kept.
--  • User-agent strings are hashed; only the "family" (e.g. "Chrome 120")
--    is stored in the clear for dashboard readability.
--  • Geo data is limited to country code (ISO-3166-1 alpha-2) and optional
--    region; no lat/lng or street-level data.
--  • Signals auto-expire after ABUSE_SIGNAL_RETENTION_DAYS (default 90).

CREATE TABLE IF NOT EXISTS abuse_signals (
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- ── Privacy-safe identity ──────────────────────────────────────────────
  ip_address_hash   TEXT        NOT NULL,       -- SHA-256(request IP + salt)
  ip_address_prefix TEXT,                        -- /24 subnet prefix
  user_agent_hash   TEXT        NOT NULL,       -- SHA-256(user-agent)
  ua_family         TEXT,                        -- Parsed family e.g. "Chrome 120"

  -- ── Geo-lite (optional, privacy-redacted) ──────────────────────────────
  geo_country       TEXT,                        -- ISO 3166-1 alpha-2
  geo_region        TEXT,                        -- Region / state code

  -- ── Signal payload ─────────────────────────────────────────────────────
  action_type       TEXT        NOT NULL,
  action_outcome    TEXT        NOT NULL,
  target_username   TEXT,
  invalid_count     INTEGER     NOT NULL DEFAULT 1,

  -- ── Abuse scoring ──────────────────────────────────────────────────────
  abuse_score       REAL        NOT NULL DEFAULT 0.0,
  signal_tags       TEXT[]      DEFAULT '{}',

  -- ── Request metadata ───────────────────────────────────────────────────
  request_method    TEXT,
  request_path     TEXT,
  status_code       INTEGER,

  -- ── Lifecycle ──────────────────────────────────────────────────────────
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_until   TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '90 days')
);

COMMENT ON TABLE  abuse_signals IS
  'Privacy-safe abuse-detection signals recorded from public payment pages.';

COMMENT ON COLUMN abuse_signals.ip_address_hash IS
  'SHA-256(request IP + per-request salt). Raw IP is never persisted.';
COMMENT ON COLUMN abuse_signals.ip_address_prefix IS
  '/24 subnet prefix for coarse grouping (e.g. "192.168.1.0").';
COMMENT ON COLUMN abuse_signals.user_agent_hash IS
  'SHA-256(user-agent). Stored for repeat-detection without retaining the full UA.';
COMMENT ON COLUMN abuse_signals.ua_family IS
  'Readable UA family tag (e.g. "Chrome 120") — safe for dashboards.';
COMMENT ON COLUMN abuse_signals.geo_country IS
  'ISO 3166-1 alpha-2 country code from geo-lite lookup. Never lat/lng.';
COMMENT ON COLUMN abuse_signals.geo_region IS
  'Optional region/state code. Redacted when privacy regulations require it.';
COMMENT ON COLUMN abuse_signals.action_type IS
  'The payment-page action: payment_link_status, link_metadata, payment_submit.';
COMMENT ON COLUMN abuse_signals.action_outcome IS
  'Result: success, invalid_params, not_found, rate_limited, error.';
COMMENT ON COLUMN abuse_signals.invalid_count IS
  'Rolling count of invalid actions from this IP/UA fingerprint pair.';
COMMENT ON COLUMN abuse_signals.abuse_score IS
  'Computed lightweight abuse score (0–100). Higher = more suspicious.';
COMMENT ON COLUMN abuse_signals.signal_tags IS
  'Tags: scraping, brute_force, replay, geo_anomaly, unknown_ua.';
COMMENT ON COLUMN abuse_signals.retention_until IS
  'Auto-expiry date. Signals are pruned after this timestamp.';

-- ── Operator query indexes ───────────────────────────────────────────────
-- Find recent signals for a given IP fingerprint.
CREATE INDEX IF NOT EXISTS idx_as_ip_hash_created
  ON abuse_signals (ip_address_hash, created_at DESC);

-- Dashboard: surface high-score signals first.
CREATE INDEX IF NOT EXISTS idx_as_high_score
  ON abuse_signals (abuse_score DESC)
  WHERE abuse_score >= 20;

-- Per-username abuse view.
CREATE INDEX IF NOT EXISTS idx_as_target_username
  ON abuse_signals (target_username, created_at DESC)
  WHERE target_username IS NOT NULL;

-- Retention sweeper.
CREATE INDEX IF NOT EXISTS idx_as_retention
  ON abuse_signals (retention_until)
  WHERE retention_until < now();

-- Grouped counts for aggregation queries.
CREATE INDEX IF NOT EXISTS idx_as_outcome_action
  ON abuse_signals (action_outcome, action_type, created_at DESC);
