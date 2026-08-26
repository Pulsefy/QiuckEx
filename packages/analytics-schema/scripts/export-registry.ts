import { zodToJsonSchema } from 'zod-to-json-schema';
import * as fs from 'fs';
import * as path from 'path';
import { AnalyticsRegistry } from '../src/schemas';
import { z } from 'zod';

const FullRegistrySchema = z.object(AnalyticsRegistry);

// @ts-ignore - Ignore deep instantiation errors
const jsonSchema = zodToJsonSchema(FullRegistrySchema as any, 'AnalyticsRegistry');

const outputPath = path.join(__dirname, '../../analytics-registry.json');
fs.writeFileSync(outputPath, JSON.stringify(jsonSchema, null, 2));

console.log(`Successfully exported schema registry to ${outputPath}`);
