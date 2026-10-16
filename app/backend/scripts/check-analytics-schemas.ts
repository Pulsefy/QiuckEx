/**
 * Standalone CI check for analytics event schema registry compatibility.
 *
 * Usage:
 *   pnpm --filter @quickex/backend run check:analytics-schemas
 *
 * Exits with code 1 when a required field is added or a field is removed
 * (or modified incompatibly) without incrementing the event schema version.
 */
import {
  ANALYTICS_EVENT_SCHEMAS,
  assertAnalyticsSchemasCompatible,
  loadBaselineSchemaSnapshot,
} from '../src/analytics/events';

function main(): void {
  const baseline = loadBaselineSchemaSnapshot();
  assertAnalyticsSchemasCompatible(baseline, ANALYTICS_EVENT_SCHEMAS);
  console.log(
    `Analytics schema registry check passed (${Object.keys(ANALYTICS_EVENT_SCHEMAS).length} versioned event schemas verified).`,
  );
}

main();
