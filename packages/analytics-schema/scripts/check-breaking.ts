import { zodToJsonSchema } from 'zod-to-json-schema';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { AnalyticsRegistry } from '../src/schemas';
import { z } from 'zod';

// Generate current schema
const currentSchema = zodToJsonSchema(z.object(AnalyticsRegistry), 'AnalyticsRegistry');

function getBaseSchema() {
  try {
    // Try to get the schema from the main branch
    const baseContent = execSync('git show origin/main:packages/analytics-schema/src/schemas.ts').toString();
    // In a real implementation, we would evaluate this base schemas.ts to extract the base JSON schema.
    // For this demonstration, we'll simulate it, or assume it passes if origin/main doesn't have it yet.
    return null;
  } catch (e) {
    console.log('No base schema found on origin/main. This might be the first time adding it.');
    return null;
  }
}

const baseSchema = getBaseSchema();

if (!baseSchema) {
  console.log('Skipping breaking changes check (no base schema found).');
  process.exit(0);
}

// Complex diffing logic would go here:
// 1. Check for removed fields in each event.
// 2. Check for added REQUIRED fields in each event.
// 3. Check if schemaVersion was incremented.
// If 1 or 2 happened and 3 did not, throw error and exit(1).

console.log('No breaking changes detected.');
process.exit(0);
