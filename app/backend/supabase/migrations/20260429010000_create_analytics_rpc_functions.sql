-- Analytics RPC functions for dashboard insights and financial exports (Issue #211)
--
-- Provides SQL-level aggregation for:
-- 1) Summary metrics including conversion rate and total USD volume
-- 2) Asset distribution percentages
-- 3) Time-series buckets (daily, weekly, monthly) for charts

-- ---------------------------------------------------------------------------
-- Summary aggregation (USD equivalent + conversion rate)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION quickex_analytics_summary(
  p_public_key TEXT,
  p_start_date TIMESTAMPTZ,
  p_end_date TIMESTAMPTZ
)
RETURNS TABLE (
  total_transactions BIGINT,
  successful_transactions BIGINT,
  failed_transactions BIGINT,
  conversion_rate NUMERIC,
  total_volume_usd NUMERIC,
  average_transaction_usd NUMERIC
)
LANGUAGE sql
STABLE
AS $$
  WITH filtered AS (
    SELECT
      COALESCE(amount_usd, amount::NUMERIC, 0) AS amount_usd_norm,
      LOWER(COALESCE(status, 'unknown')) AS status_norm
    FROM payment_records
    WHERE
      (sender_public_key = p_public_key OR receiver_public_key = p_public_key)
      AND created_at >= p_start_date
      AND created_at <= p_end_date
  )
  SELECT
    COUNT(*)::BIGINT AS total_transactions,
    COUNT(*) FILTER (
      WHERE status_norm IN ('paid', 'completed', 'success', 'settled', 'confirmed')
    )::BIGINT AS successful_transactions,
    COUNT(*) FILTER (
      WHERE status_norm IN ('failed', 'error', 'cancelled', 'rejected')
    )::BIGINT AS failed_transactions,
    COALESCE(
      ROUND(
        (
          COUNT(*) FILTER (
            WHERE status_norm IN ('paid', 'completed', 'success', 'settled', 'confirmed')
          )::NUMERIC
          / NULLIF(COUNT(*)::NUMERIC, 0)
        ) * 100,
        2
      ),
      0
    ) AS conversion_rate,
    COALESCE(ROUND(SUM(amount_usd_norm), 2), 0) AS total_volume_usd,
    COALESCE(ROUND(AVG(amount_usd_norm), 2), 0) AS average_transaction_usd
  FROM filtered;
$$;

-- ---------------------------------------------------------------------------
-- Asset distribution aggregation
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION quickex_analytics_asset_distribution(
  p_public_key TEXT,
  p_start_date TIMESTAMPTZ,
  p_end_date TIMESTAMPTZ
)
RETURNS TABLE (
  asset TEXT,
  volume_usd NUMERIC,
  percentage NUMERIC,
  transaction_count BIGINT
)
LANGUAGE sql
STABLE
AS $$
  WITH filtered AS (
    SELECT
      UPPER(COALESCE(asset, 'XLM')) AS asset_norm,
      COALESCE(amount_usd, amount::NUMERIC, 0) AS amount_usd_norm
    FROM payment_records
    WHERE
      (sender_public_key = p_public_key OR receiver_public_key = p_public_key)
      AND created_at >= p_start_date
      AND created_at <= p_end_date
  ),
  totals AS (
    SELECT COALESCE(SUM(amount_usd_norm), 0) AS total_volume FROM filtered
  )
  SELECT
    f.asset_norm AS asset,
    ROUND(SUM(f.amount_usd_norm), 2) AS volume_usd,
    COALESCE(
      ROUND((SUM(f.amount_usd_norm) / NULLIF(t.total_volume, 0)) * 100, 2),
      0
    ) AS percentage,
    COUNT(*)::BIGINT AS transaction_count
  FROM filtered f
  CROSS JOIN totals t
  GROUP BY f.asset_norm, t.total_volume
  ORDER BY volume_usd DESC;
$$;

-- ---------------------------------------------------------------------------
-- Time-series aggregation (daily/weekly/monthly)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION quickex_analytics_time_series(
  p_public_key TEXT,
  p_start_date TIMESTAMPTZ,
  p_end_date TIMESTAMPTZ,
  p_interval TEXT DEFAULT 'daily'
)
RETURNS TABLE (
  period TEXT,
  transaction_count BIGINT,
  successful_transactions BIGINT,
  volume_usd NUMERIC,
  volume_usdc NUMERIC,
  volume_xlm NUMERIC,
  asset_volumes JSONB
)
LANGUAGE sql
STABLE
AS $$
  WITH filtered AS (
    SELECT
      created_at,
      UPPER(COALESCE(asset, 'XLM')) AS asset_norm,
      COALESCE(amount_usd, amount::NUMERIC, 0) AS amount_usd_norm,
      LOWER(COALESCE(status, 'unknown')) AS status_norm
    FROM payment_records
    WHERE
      (sender_public_key = p_public_key OR receiver_public_key = p_public_key)
      AND created_at >= p_start_date
      AND created_at <= p_end_date
  ),
  bucketed AS (
    SELECT
      CASE
        WHEN LOWER(p_interval) = 'monthly' THEN to_char(date_trunc('month', created_at), 'YYYY-MM')
        WHEN LOWER(p_interval) = 'weekly' THEN to_char(date_trunc('week', created_at), 'IYYY-"W"IW')
        ELSE to_char(date_trunc('day', created_at), 'YYYY-MM-DD')
      END AS period_key,
      asset_norm,
      amount_usd_norm,
      status_norm
    FROM filtered
  ),
  grouped AS (
    SELECT
      period_key,
      COUNT(*)::BIGINT AS tx_count,
      COUNT(*) FILTER (
        WHERE status_norm IN ('paid', 'completed', 'success', 'settled', 'confirmed')
      )::BIGINT AS success_count,
      ROUND(SUM(amount_usd_norm), 2) AS volume_total,
      ROUND(SUM(amount_usd_norm) FILTER (WHERE asset_norm = 'USDC'), 2) AS vol_usdc,
      ROUND(SUM(amount_usd_norm) FILTER (WHERE asset_norm = 'XLM'), 2) AS vol_xlm
    FROM bucketed
    GROUP BY period_key
  ),
  assets_per_period AS (
    SELECT
      period_key,
      jsonb_object_agg(asset_norm, rounded_volume) AS asset_map
    FROM (
      SELECT
        period_key,
        asset_norm,
        ROUND(SUM(amount_usd_norm), 2) AS rounded_volume
      FROM bucketed
      GROUP BY period_key, asset_norm
    ) x
    GROUP BY period_key
  )
  SELECT
    g.period_key AS period,
    g.tx_count AS transaction_count,
    g.success_count AS successful_transactions,
    COALESCE(g.volume_total, 0) AS volume_usd,
    COALESCE(g.vol_usdc, 0) AS volume_usdc,
    COALESCE(g.vol_xlm, 0) AS volume_xlm,
    COALESCE(a.asset_map, '{}'::jsonb) AS asset_volumes
  FROM grouped g
  LEFT JOIN assets_per_period a
    ON a.period_key = g.period_key
  ORDER BY g.period_key ASC;
$$;

