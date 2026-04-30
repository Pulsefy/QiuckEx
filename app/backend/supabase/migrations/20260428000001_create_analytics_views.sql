-- Migration: Create materialized views for analytics
-- This migration creates materialized views to optimize analytics queries
-- and prevent excessive load on the main transaction tables

-- Create the daily_metrics materialized view
CREATE MATERIALIZED VIEW IF NOT EXISTS daily_metrics AS
SELECT
  DATE(created_at) as metric_date,
  asset_code,
  asset_issuer,
  COUNT(*) as transaction_count,
  COUNT(CASE WHEN status = 'success' THEN 1 END) as success_count,
  SUM(CASE WHEN status = 'success' THEN amount::numeric ELSE 0 END) as total_volume,
  AVG(CASE WHEN status = 'success' THEN amount::numeric ELSE 0 END) as avg_amount,
  MIN(fee_paid::numeric) as min_fee,
  MAX(fee_paid::numeric) as max_fee,
  SUM(fee_paid::numeric) as total_fees,
  COUNT(DISTINCT CASE WHEN status = 'success' THEN link_id ELSE NULL END) as unique_paid_links,
  COUNT(DISTINCT link_id) as unique_active_links,
  CREATED_AT as view_updated_at
FROM stellar_ingestion
WHERE created_at IS NOT NULL
GROUP BY DATE(created_at), asset_code, asset_issuer
ORDER BY metric_date DESC;

-- Create index on daily_metrics for faster queries
CREATE INDEX IF NOT EXISTS idx_daily_metrics_date_asset 
ON daily_metrics(metric_date DESC, asset_code);

-- Create the weekly_metrics materialized view
CREATE MATERIALIZED VIEW IF NOT EXISTS weekly_metrics AS
SELECT
  DATE_TRUNC('week', created_at) as week_start,
  DATE_TRUNC('week', created_at) + INTERVAL '6 days 23 hours 59 minutes 59 seconds' as week_end,
  asset_code,
  asset_issuer,
  COUNT(*) as transaction_count,
  COUNT(CASE WHEN status = 'success' THEN 1 END) as success_count,
  SUM(CASE WHEN status = 'success' THEN amount::numeric ELSE 0 END) as total_volume,
  AVG(CASE WHEN status = 'success' THEN amount::numeric ELSE 0 END) as avg_amount,
  SUM(fee_paid::numeric) as total_fees,
  COUNT(DISTINCT CASE WHEN status = 'success' THEN link_id ELSE NULL END) as unique_paid_links,
  COUNT(DISTINCT link_id) as unique_active_links
FROM stellar_ingestion
WHERE created_at IS NOT NULL
GROUP BY DATE_TRUNC('week', created_at), asset_code, asset_issuer
ORDER BY week_start DESC;

-- Create index on weekly_metrics
CREATE INDEX IF NOT EXISTS idx_weekly_metrics_week_asset
ON weekly_metrics(week_start DESC, asset_code);

-- Create the monthly_metrics materialized view
CREATE MATERIALIZED VIEW IF NOT EXISTS monthly_metrics AS
SELECT
  DATE_TRUNC('month', created_at) as month_start,
  DATE_TRUNC('month', created_at) + INTERVAL '1 month' - INTERVAL '1 day 23 hours 59 minutes 59 seconds' as month_end,
  asset_code,
  asset_issuer,
  COUNT(*) as transaction_count,
  COUNT(CASE WHEN status = 'success' THEN 1 END) as success_count,
  SUM(CASE WHEN status = 'success' THEN amount::numeric ELSE 0 END) as total_volume,
  AVG(CASE WHEN status = 'success' THEN amount::numeric ELSE 0 END) as avg_amount,
  SUM(fee_paid::numeric) as total_fees,
  COUNT(DISTINCT CASE WHEN status = 'success' THEN link_id ELSE NULL END) as unique_paid_links,
  COUNT(DISTINCT link_id) as unique_active_links
FROM stellar_ingestion
WHERE created_at IS NOT NULL
GROUP BY DATE_TRUNC('month', created_at), asset_code, asset_issuer
ORDER BY month_start DESC;

-- Create index on monthly_metrics
CREATE INDEX IF NOT EXISTS idx_monthly_metrics_month_asset
ON monthly_metrics(month_start DESC, asset_code);

-- Create a view for organization-scoped metrics aggregation
-- This helps with authorization and scoping analytics to organizations
CREATE OR REPLACE VIEW organization_metrics_daily AS
SELECT
  si.organization_id,
  dm.metric_date,
  dm.asset_code,
  dm.asset_issuer,
  dm.transaction_count,
  dm.success_count,
  dm.total_volume,
  dm.avg_amount,
  dm.min_fee,
  dm.max_fee,
  dm.total_fees,
  dm.unique_paid_links,
  dm.unique_active_links
FROM daily_metrics dm
INNER JOIN stellar_ingestion si ON 
  DATE(si.created_at) = dm.metric_date 
  AND si.asset_code = dm.asset_code
  AND (si.asset_issuer = dm.asset_issuer OR (si.asset_issuer IS NULL AND dm.asset_issuer IS NULL))
GROUP BY si.organization_id, dm.metric_date, dm.asset_code, dm.asset_issuer,
  dm.transaction_count, dm.success_count, dm.total_volume, dm.avg_amount,
  dm.min_fee, dm.max_fee, dm.total_fees, dm.unique_paid_links, dm.unique_active_links;

-- Create a function to refresh all analytics views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY daily_metrics;
  REFRESH MATERIALIZED VIEW CONCURRENTLY weekly_metrics;
  REFRESH MATERIALIZED VIEW CONCURRENTLY monthly_metrics;
END;
$$ LANGUAGE plpgsql;

-- Create indexes for better query performance on stellar_ingestion
CREATE INDEX IF NOT EXISTS idx_stellar_ingestion_created_asset 
ON stellar_ingestion(created_at DESC, asset_code);

CREATE INDEX IF NOT EXISTS idx_stellar_ingestion_org_created
ON stellar_ingestion(organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stellar_ingestion_link_created
ON stellar_ingestion(link_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stellar_ingestion_status
ON stellar_ingestion(status, created_at DESC);

-- Grant appropriate permissions
-- Note: Adjust role names and permissions as needed for your setup
GRANT SELECT ON daily_metrics TO postgres;
GRANT SELECT ON weekly_metrics TO postgres;
GRANT SELECT ON monthly_metrics TO postgres;
GRANT SELECT ON organization_metrics_daily TO postgres;

-- Refresh the materialized views
SELECT refresh_analytics_views();

-- Add a comment describing the views
COMMENT ON MATERIALIZED VIEW daily_metrics IS 
  'Aggregated daily metrics by asset. Used for analytics API. Refresh periodically.';
COMMENT ON MATERIALIZED VIEW weekly_metrics IS 
  'Aggregated weekly metrics by asset. Used for analytics API. Refresh periodically.';
COMMENT ON MATERIALIZED VIEW monthly_metrics IS 
  'Aggregated monthly metrics by asset. Used for analytics API. Refresh periodically.';
COMMENT ON FUNCTION refresh_analytics_views() IS 
  'Refresh all analytics materialized views. Call periodically (e.g., via cron job every 5 minutes).';
