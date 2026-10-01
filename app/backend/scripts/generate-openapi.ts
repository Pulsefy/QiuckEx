import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import * as fs from "fs";
import * as path from "path";

async function bootstrap() {
  // Use dummy environment variables to allow bootstrap in CI without real DB
  process.env.SUPABASE_URL = process.env.SUPABASE_URL || "https://test.supabase.co";
  process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "test-key";
  process.env.NETWORK = process.env.NETWORK || "testnet";
  process.env.SKIP_DB = process.env.SKIP_DB || "true";
  
  // Prevent IngestionBootstrapService from starting streams
  delete process.env.QUICKEX_CONTRACT_ID;

  const { AppModule } = await import("../src/app.module");

  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn', 'debug', 'log'] });

  const swaggerConfig = new DocumentBuilder()
    .setTitle("QuickEx Backend")
    .setDescription("QuickEx API documentation")
    .setVersion("v1")
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  
  // Read allowlist
  const allowlistPath = path.join(__dirname, "..", "openapi-allowlist.json");
  let routeAllowlist: string[] = [];
  if (fs.existsSync(allowlistPath)) {
    routeAllowlist = JSON.parse(fs.readFileSync(allowlistPath, "utf-8"));
  }

  const autoUpdate = process.env.CI_UPDATE_ALLOWLIST === "true";
  const newAllowlist = new Set<string>(routeAllowlist);
  let hasErrors = false;

  // 1. Validate paths have responses
  for (const [routePath, pathItem] of Object.entries(document.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem)) {
      const op = operation as any;
      const identifier = `${routePath} (${method.toUpperCase()})`;
      
      if (routeAllowlist.includes(identifier)) {
        continue;
      }

      let routeHasError = false;
      const responses = op.responses || {};
      const hasSuccessResponse = Object.keys(responses).some(code => code.startsWith("2"));
      
      if (!hasSuccessResponse) {
        console.error(`ERROR: Route ${identifier} is missing a success response schema.`);
        routeHasError = true;
      } else {
        // Ensure success responses have schemas if they have content
        for (const [code, resp] of Object.entries(responses)) {
          if (code.startsWith("2")) {
            const content = (resp as any).content;
            if (content && content["application/json"]) {
               const schema = content["application/json"].schema;
               if (!schema) {
                 console.error(`ERROR: Route ${identifier} is missing a schema in its success response content.`);
                 routeHasError = true;
               }
            } else if (code !== "204") {
               if (!content && method.toUpperCase() !== "DELETE") {
                 console.error(`ERROR: Route ${identifier} returns ${code} but is missing response schema/content definition.`);
                 routeHasError = true;
               }
            }
          }
        }
      }

      if (routeHasError) {
        if (autoUpdate) {
          newAllowlist.add(identifier);
        } else {
          hasErrors = true;
        }
      }
    }
  }

  // 2. Validate DTO fields have types (in components.schemas)
  const schemas = document.components?.schemas || {};
  for (const [schemaName, schemaObj] of Object.entries(schemas)) {
    const props = (schemaObj as any).properties || {};
    for (const [propName, propDef] of Object.entries(props)) {
      const def = propDef as any;
      if (!def.type && !def.$ref && !def.allOf && !def.oneOf && !def.anyOf && !def.enum && !def.properties && !def.additionalProperties && !def.items) {
        console.error(`ERROR: DTO field ${schemaName}.${propName} is missing a type. Add @ApiProperty({ type: ... })`);
        if (!autoUpdate) {
          hasErrors = true;
        }
      }
    }
  }

  if (autoUpdate && newAllowlist.size > routeAllowlist.length) {
    fs.writeFileSync(allowlistPath, JSON.stringify(Array.from(newAllowlist).sort(), null, 2));
    console.log(`Updated openapi-allowlist.json with ${newAllowlist.size - routeAllowlist.length} new undocumented routes.`);
  }

  // Always write out the openapi spec so it can be published as an artifact
  const outputPath = path.join(__dirname, "..", "openapi.json");
  fs.writeFileSync(outputPath, JSON.stringify(document, null, 2));
  console.log(`OpenAPI spec generated and saved to ${outputPath}`);

  await app.close();

  if (hasErrors) {
    console.error("OpenAPI Validation failed. See errors above.");
    process.exit(1);
  } else {
    console.log("OpenAPI Validation passed.");
    process.exit(0); // Force exit to prevent background jobs from hanging the CI
  }
}

bootstrap().catch((err) => {
  console.error("Fatal error generating OpenAPI spec:");
  console.error(err);
  if (err instanceof Error && err.stack) {
    console.error(err.stack);
  }
  process.exit(1);
});
