import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { AppModule } from "../src/app.module";
import * as fs from "fs";
import * as path from "path";

async function bootstrap() {
  // Use dummy environment variables to allow bootstrap in CI without real DB
  process.env.SUPABASE_URL = process.env.SUPABASE_URL || "https://test.supabase.co";
  process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "test-key";
  process.env.NETWORK = process.env.NETWORK || "testnet";

  const app = await NestFactory.create(AppModule, { logger: false });

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

  let hasErrors = false;

  // 1. Validate paths have responses
  for (const [routePath, pathItem] of Object.entries(document.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem)) {
      const op = operation as any;
      const identifier = `${routePath} (${method.toUpperCase()})`;
      
      if (routeAllowlist.includes(identifier)) {
        continue;
      }

      const responses = op.responses || {};
      const hasSuccessResponse = Object.keys(responses).some(code => code.startsWith("2"));
      
      if (!hasSuccessResponse) {
        console.error(`ERROR: Route ${identifier} is missing a success response schema.`);
        hasErrors = true;
      } else {
        // Ensure success responses have schemas if they have content
        for (const [code, resp] of Object.entries(responses)) {
          if (code.startsWith("2")) {
            const content = (resp as any).content;
            if (content && content["application/json"]) {
               const schema = content["application/json"].schema;
               if (!schema) {
                 console.error(`ERROR: Route ${identifier} is missing a schema in its success response content.`);
                 hasErrors = true;
               }
            } else if (code !== "204") {
               // Usually APIs should define a response body unless it's 204 No Content
               if (!content && method.toUpperCase() !== "DELETE") {
                 // But wait, the requirement is just: "route is missing a response schema"
                 // If a route returns 200 but doesn't document the schema, that's what we want to catch.
                 // However, NestJS default swagger output for empty response doesn't have `content`.
                 // So if there's no `content` documented and it's not 204 or DELETE, it's missing.
                 console.error(`ERROR: Route ${identifier} returns ${code} but is missing response schema/content definition.`);
                 hasErrors = true;
               }
            }
          }
        }
      }
    }
  }

  // 2. Validate DTO fields have types (in components.schemas)
  const schemas = document.components?.schemas || {};
  for (const [schemaName, schemaObj] of Object.entries(schemas)) {
    // If a schema is in allowlist, we can skip it, but let's check all documented schemas
    const props = (schemaObj as any).properties || {};
    for (const [propName, propDef] of Object.entries(props)) {
      const def = propDef as any;
      if (!def.type && !def.$ref && !def.allOf && !def.oneOf && !def.anyOf) {
        console.error(`ERROR: DTO field ${schemaName}.${propName} is missing a type. Add @ApiProperty({ type: ... })`);
        hasErrors = true;
      }
    }
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
  }
}

bootstrap().catch((err) => {
  console.error("Fatal error generating OpenAPI spec:", err);
  process.exit(1);
});
