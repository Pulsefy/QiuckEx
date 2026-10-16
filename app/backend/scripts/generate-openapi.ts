#!/usr/bin/env ts-node
/**
 * Script to generate OpenAPI specification document from NestJS application metadata.
 *
 * Usage:
 *   ts-node scripts/generate-openapi.ts [output-path]
 *
 * Default output path:
 *   docs/openapi-generated.json
 */

import { NestFactory } from '@nestjs/core';
import * as fs from 'fs';
import * as path from 'path';

// Set mandatory environment variables so AppModule boots cleanly in CI
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.STELLAR_NETWORK = process.env.STELLAR_NETWORK || 'testnet';
process.env.NETWORK = process.env.NETWORK || 'testnet';
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://test.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'test-anon-key';
process.env.ENABLE_RECONCILIATION_MODULE = 'true';
process.env.ENABLE_NOTIFICATIONS_MODULE = 'true';
process.env.ENABLE_DEVELOPER_MODULE = 'true';

async function generateOpenApiSpec() {
  const { AppModule } = await import('../src/app.module');
  const { createSwaggerDocument } = await import('../src/config/swagger.config');

  console.log('[openapi:generate] Initializing NestJS application context...');
  const app = await NestFactory.create(AppModule, {
    logger: false, // Suppress startup noise
  });

  console.log('[openapi:generate] Extracting OpenAPI metadata...');
  const document = createSwaggerDocument(app, process.env.NETWORK || 'testnet');

  const defaultOutPath = path.resolve(__dirname, '..', 'docs', 'openapi-generated.json');
  const targetPath = process.argv[2] ? path.resolve(process.argv[2]) : defaultOutPath;

  const targetDir = path.dirname(targetPath);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  fs.writeFileSync(targetPath, JSON.stringify(document, null, 2), 'utf-8');
  console.log(`[openapi:generate] Successfully generated OpenAPI spec at: ${targetPath}`);

  await app.close();
}

generateOpenApiSpec().catch((err) => {
  console.error('[openapi:generate] Failed to generate OpenAPI spec:', err);
  process.exit(1);
});
