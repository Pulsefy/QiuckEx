#!/usr/bin/env ts-node
/**
 * OpenAPI Schema CI Gate
 *
 * Verifies that:
 * 1. Every route in the OpenAPI spec has a response schema definition, or is covered by the allowlist.
 * 2. Every schema/DTO field has an explicit type definition (type, $ref, or items).
 *
 * Exit 0 if all validations pass.
 * Exit 1 if violations are found.
 */

import * as fs from 'fs';
import * as path from 'path';

interface AllowlistEntry {
  path: string;
  method: string;
  reason: string;
}

interface AllowlistSchemaEntry {
  schema: string;
  property: string;
  reason: string;
}

interface Allowlist {
  routes: AllowlistEntry[];
  schemas: AllowlistSchemaEntry[];
}

export interface RouteViolation {
  path: string;
  method: string;
  reason: string;
}

export interface SchemaViolation {
  schemaName: string;
  propertyName: string;
  reason: string;
}

export function validateOpenApiDocument(
  spec: any,
  allowlist: Allowlist,
): { routeViolations: RouteViolation[]; schemaViolations: SchemaViolation[] } {
  const routeViolations: RouteViolation[] = [];
  const schemaViolations: SchemaViolation[] = [];

  const allowedRoutes = new Set(
    (allowlist.routes || []).map((r) => `${r.method.toLowerCase()} ${r.path}`),
  );

  const allowedSchemas = new Set(
    (allowlist.schemas || []).map((s) => `${s.schema}.${s.property}`),
  );

  // 1. Validate routes for response schema annotations
  const paths = spec.paths || {};
  const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

  for (const [routePath, methods] of Object.entries<any>(paths)) {
    for (const [method, operation] of Object.entries<any>(methods)) {
      if (!httpMethods.includes(method.toLowerCase())) {
        continue;
      }

      const routeKey = `${method.toLowerCase()} ${routePath}`;
      if (allowedRoutes.has(routeKey)) {
        continue;
      }

      const responses = operation.responses;
      if (!responses || Object.keys(responses).length === 0) {
        routeViolations.push({
          path: routePath,
          method: method.toUpperCase(),
          reason: 'No response annotations found on route',
        });
        continue;
      }

      // Check success responses (200, 201, 204, or default)
      const successStatuses = ['200', '201', '204', 'default'];
      const matchingStatus = Object.keys(responses).find((code) => successStatuses.includes(code));

      if (!matchingStatus) {
        routeViolations.push({
          path: routePath,
          method: method.toUpperCase(),
          reason: `No success response code (200/201/204) declared. Declared codes: ${Object.keys(responses).join(', ')}`,
        });
        continue;
      }

      if (matchingStatus === '204') {
        // 204 No Content legitimately has no body schema
        continue;
      }

      const responseObj = responses[matchingStatus];
      const hasSchema =
        responseObj.schema ||
        (responseObj.content &&
          Object.values(responseObj.content).some(
            (mediaType: any) => mediaType.schema && (mediaType.schema.$ref || mediaType.schema.type || mediaType.schema.items),
          ));

      if (!hasSchema) {
        routeViolations.push({
          path: routePath,
          method: method.toUpperCase(),
          reason: `Response ${matchingStatus} is missing a response schema/DTO definition`,
        });
      }
    }
  }

  // 2. Validate DTO components for missing property types
  const schemas = spec.components?.schemas || {};
  for (const [schemaName, schemaObj] of Object.entries<any>(schemas)) {
    const properties = schemaObj.properties || {};
    for (const [propName, propDef] of Object.entries<any>(properties)) {
      const schemaKey = `${schemaName}.${propName}`;
      if (allowedSchemas.has(schemaKey)) {
        continue;
      }

      const hasType =
        Boolean(propDef.type) ||
        Boolean(propDef.$ref) ||
        Boolean(propDef.allOf) ||
        Boolean(propDef.anyOf) ||
        Boolean(propDef.oneOf) ||
        (propDef.items && (propDef.items.type || propDef.items.$ref));

      if (!hasType) {
        schemaViolations.push({
          schemaName,
          propertyName: propName,
          reason: 'DTO field is missing a type or $ref annotation',
        });
      }
    }
  }

  return { routeViolations, schemaViolations };
}

function run() {
  const specPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve(__dirname, '..', 'docs', 'openapi-generated.json');

  const allowlistPath = path.resolve(
    __dirname,
    '..',
    'docs',
    'openapi-schema-allowlist.json',
  );

  console.log(`[openapi:check] Reading OpenAPI spec from: ${specPath}`);
  if (!fs.existsSync(specPath)) {
    console.error(`[openapi:check] Error: Spec file does not exist at ${specPath}`);
    console.error('[openapi:check] Please run "pnpm run openapi:generate" first.');
    process.exit(1);
  }

  const spec = JSON.parse(fs.readFileSync(specPath, 'utf-8'));

  let allowlist: Allowlist = { routes: [], schemas: [] };
  if (fs.existsSync(allowlistPath)) {
    console.log(`[openapi:check] Loading allowlist from: ${allowlistPath}`);
    allowlist = JSON.parse(fs.readFileSync(allowlistPath, 'utf-8'));
  }

  const { routeViolations, schemaViolations } = validateOpenApiDocument(spec, allowlist);

  let hasError = false;

  if (routeViolations.length > 0) {
    hasError = true;
    console.error(`\n❌ [openapi:check] Found ${routeViolations.length} route(s) missing response schemas:`);
    for (const v of routeViolations) {
      console.error(`  - ${v.method} ${v.path}: ${v.reason}`);
    }
  }

  if (schemaViolations.length > 0) {
    hasError = true;
    console.error(`\n❌ [openapi:check] Found ${schemaViolations.length} DTO property(ies) missing types:`);
    for (const v of schemaViolations) {
      console.error(`  - ${v.schemaName}.${v.propertyName}: ${v.reason}`);
    }
  }

  if (hasError) {
    console.error('\nOpenAPI schema CI gate check FAILED.');
    console.error('If an exclusion is intentional (e.g., internal-only or streaming route), add it to:');
    console.error(`  ${allowlistPath}\n`);
    process.exit(1);
  }

  console.log('\n✅ [openapi:check] All endpoints and DTO schemas adhere to OpenAPI documentation requirements.');
}

if (require.main === module) {
  run();
}
