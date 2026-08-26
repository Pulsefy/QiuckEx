process.env.NETWORK = process.env.NETWORK || 'testnet';
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://test-project.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'test-anon-key-for-testing';
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.PORT = process.env.PORT || '4000';
process.env.RATE_LIMIT_PUBLIC_BURST_LIMIT = '1000';
process.env.RATE_LIMIT_PUBLIC_SUSTAINED_LIMIT = '1000';
process.env.RATE_LIMIT_AUTHENTICATED_BURST_LIMIT = '1000';
process.env.RATE_LIMIT_AUTHENTICATED_SUSTAINED_LIMIT = '1000';

import 'reflect-metadata';
import * as fs from 'fs';
import * as path from 'path';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from '../src/app.module';

interface AllowlistPathEntry {
  pattern: string;
  reason?: string;
}

interface Allowlist {
  paths: AllowlistPathEntry[];
  dtoFieldsSkipped?: { name: string; reason?: string }[];
}

interface ValidationFailure {
  type: 'missing_response_schema' | 'missing_request_schema' | 'untyped_dto_field';
  path?: string;
  method?: string;
  statusCode?: string;
  dtoName?: string;
  fieldName?: string;
  message: string;
}

const ALLOWLIST_PATH = path.join(__dirname, 'openapi-allowlist.json');
const OUTPUT_DIR = path.join(process.cwd(), 'dist-openapi');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'openapi.json');

function loadAllowlist(): Allowlist {
  try {
    const raw = fs.readFileSync(ALLOWLIST_PATH, 'utf-8');
    return JSON.parse(raw) as Allowlist;
  } catch (err) {
    console.warn(`[openapi-gate] Could not read allowlist at ${ALLOWLIST_PATH}, continuing without it.`);
    return { paths: [] };
  }
}

function isPathAllowlisted(pathToCheck: string, allowlist: Allowlist): boolean {
  return allowlist.paths.some(entry => {
    try {
      const regex = new RegExp(entry.pattern);
      return regex.test(pathToCheck);
    } catch {
      return false;
    }
  });
}

function isDtoFieldSkipped(fieldName: string, allowlist: Allowlist): boolean {
  return (allowlist.dtoFieldsSkipped || []).some(f => f.name === fieldName);
}

function validateOpenapiSpec(
  openapiDoc: any,
  allowlist: Allowlist,
): ValidationFailure[] {
  const failures: ValidationFailure[] = [];
  const paths = openapiDoc.paths || {};

  for (const pathName of Object.keys(paths)) {
    if (isPathAllowlisted(pathName, allowlist)) continue;

    const pathItem = paths[pathName];
    const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];

    for (const method of httpMethods) {
      const operation = pathItem[method];
      if (!operation) continue;

      const responses = operation.responses || {};
      const successCodes = Object.keys(responses).filter(
        c => c.startsWith('2') || c === 'default',
      );

      if (successCodes.length === 0) {
        failures.push({
          type: 'missing_response_schema',
          path: pathName,
          method: method.toUpperCase(),
          message: `No 2xx response defined for ${method.toUpperCase()} ${pathName}`,
        });
        continue;
      }

      for (const code of successCodes) {
        const response = responses[code];
        const content = response?.content || {};
        const jsonContent = content['application/json'];

        if (!jsonContent || !jsonContent.schema) {
          const description = response?.description;
          if (!description || description.length < 3) {
            failures.push({
              type: 'missing_response_schema',
              path: pathName,
              method: method.toUpperCase(),
              statusCode: code,
              message: `Missing application/json response schema for ${method.toUpperCase()} ${pathName} (status ${code}). Add @ApiResponse({ type: ... }) or a DTO reference.`,
            });
          }
        }
      }

      if (operation.requestBody) {
        const rb = operation.requestBody as any;
        const content = rb.content || {};
        const jsonContent = content['application/json'];
        if (jsonContent && !jsonContent.schema && rb.required !== false) {
          failures.push({
            type: 'missing_request_schema',
            path: pathName,
            method: method.toUpperCase(),
            message: `Request body for ${method.toUpperCase()} ${pathName} has no schema defined. Use @ApiBody({ type: SomeDto }) or ensure body DTO is a class with @ApiProperty decorators.`,
          });
        }
      }
    }
  }

  const schemas = (openapiDoc.components && openapiDoc.components.schemas) || {};
  for (const dtoName of Object.keys(schemas)) {
    const schema = schemas[dtoName];
    if (!schema || !schema.properties) continue;

    const requiredFields: string[] = schema.required || [];
    for (const fieldName of Object.keys(schema.properties)) {
      if (isDtoFieldSkipped(fieldName, allowlist)) continue;
      const field = schema.properties[fieldName];
      const hasType = !!field.type || !!field.$ref || !!field.allOf || !!field.oneOf || !!field.anyOf;
      if (!hasType && requiredFields.includes(fieldName)) {
        failures.push({
          type: 'untyped_dto_field',
          dtoName,
          fieldName,
          message: `DTO field ${dtoName}.${fieldName} is required but has no type defined in the OpenAPI spec. Add @ApiProperty() with an explicit type.`,
        });
      }
    }
  }

  return failures;
}

async function main() {
  const allowlist = loadAllowlist();
  const allowlistedCount = allowlist.paths.length;
  console.log(`[openapi-gate] Loaded allowlist with ${allowlistedCount} path patterns.`);

  console.log('[openapi-gate] Bootstrapping Nest application for spec generation...');

  let app;
  try {
    app = await NestFactory.create(AppModule, {
      logger: ['error', 'warn', 'log'],
      rawBody: true,
    });
  } catch (bootstrapErr) {
    console.error('[openapi-gate] Failed to bootstrap application.');
    console.error(bootstrapErr);
    process.exit(1);
  }

  try {
    const swaggerConfig = new DocumentBuilder()
      .setTitle('QuickEx Backend')
      .setDescription('QuickEx API documentation - generated by CI gate')
      .setVersion('v1')
      .addTag('health')
      .addTag('usernames')
      .addTag('links')
      .addTag('transactions')
      .addTag('scam-alerts')
      .addTag('analytics')
      .addTag('metrics')
      .addTag('stellar')
      .addTag('contracts')
      .addTag('developer')
      .build();

    const document = SwaggerModule.createDocument(app, swaggerConfig);
    const generatedPaths = Object.keys(document.paths || {}).length;
    console.log(`[openapi-gate] Spec generated with ${generatedPaths} paths.`);

    if (!fs.existsSync(OUTPUT_DIR)) {
      fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    }
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(document, null, 2), 'utf-8');
    console.log(`[openapi-gate] Spec written to ${OUTPUT_FILE}`);

    console.log('[openapi-gate] Running OpenAPI completeness gate...');
    const failures = validateOpenapiSpec(document, allowlist);

    if (failures.length === 0) {
      console.log('[openapi-gate] ✅ OpenAPI completeness gate passed.');
      process.exit(0);
    }

    console.error(`\n[openapi-gate] ❌ OpenAPI completeness gate FAILED with ${failures.length} issue(s):\n`);
    for (const f of failures) {
      const prefix = f.path && f.method ? `[${f.method} ${f.path}]` : f.dtoName ? `[DTO ${f.dtoName}]` : '';
      console.error(`  - ${prefix} ${f.message}`);
    }
    console.error(`\n[openapi-gate] Summary:`);
    console.error(`    Missing response schemas: ${failures.filter(f => f.type === 'missing_response_schema').length}`);
    console.error(`    Missing request schemas:  ${failures.filter(f => f.type === 'missing_request_schema').length}`);
    console.error(`    Untyped required fields:  ${failures.filter(f => f.type === 'untyped_dto_field').length}`);
    console.error(`\n[openapi-gate] To exclude a route intentionally, add a pattern to scripts/openapi-allowlist.json with a reason.`);
    process.exit(1);
  } finally {
    try { await app.close(); } catch {}
  }
}

void main();
