/**
 * Exports the generated OpenAPI specification to `openapi.json`.
 *
 * Used by CI to fail when the committed spec diverges from the application's
 * generated spec (see .github/workflows/backend.yml "OpenAPI spec divergence").
 *
 * Run: pnpm run docs:export
 */
import { writeFileSync } from "fs";
import { join } from "path";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";

// Provide minimal valid config so the app can boot and build the document.
process.env.NODE_ENV = process.env.NODE_ENV ?? "test";
process.env.NETWORK = process.env.NETWORK ?? "testnet";
process.env.SUPABASE_URL =
  process.env.SUPABASE_URL ?? "https://spec-export.supabase.co";
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "spec-export-key";
process.env.SENTRY_DSN = process.env.SENTRY_DSN ?? "";

import { AppModule } from "../src/app.module";
import { AppConfigService } from "../src/config";

async function main() {
  const app = await NestFactory.create(AppModule, { logger: false });

  const config = app.get(AppConfigService);
  const swaggerConfig = new DocumentBuilder()
    .setTitle("QuickEx Backend")
    .setDescription(
      "QuickEx API documentation - A Stellar-based exchange platform. " +
        `Currently connected to: ${config.network}`,
    )
    .setVersion("v1")
    .addTag("health", "Health check endpoints")
    .addTag("usernames", "Username management endpoints")
    .addTag("links", "Payment link validation and metadata endpoints")
    .addTag("transactions", "Stellar transaction and payment history")
    .addTag("scam-alerts", "Fraud detection and link scanning")
    .addTag("analytics", "Dashboard analytics, time-series insights, and report exports")
    .addTag("metrics", "Application performance and health metrics")
    .addTag("stellar", "Verified assets, path preview, Soroban preflight")
    .addTag("contracts", "Contract registry publication and discovery")
    .addTag("developer", "Developer self-service: ping, webhook testing, key management, health score")
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  const outPath = join(process.cwd(), "openapi.json");
  writeFileSync(outPath, JSON.stringify(document, null, 2));
  // eslint-disable-next-line no-console
  console.log(`OpenAPI spec written to ${outPath}`);

  await app.close();
}

void main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("Failed to export OpenAPI spec:", err);
  process.exit(1);
});
