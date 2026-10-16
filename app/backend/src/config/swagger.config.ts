import { INestApplication } from "@nestjs/common";
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from "@nestjs/swagger";

export function createSwaggerDocument(
  app: INestApplication,
  network = "testnet",
): OpenAPIObject {
  const swaggerConfig = new DocumentBuilder()
    .setTitle("QuickEx Backend")
    .setDescription(
      "QuickEx API documentation - A Stellar-based exchange platform. " +
        `Currently connected to: ${network}`,
    )
    .setVersion("v1")
    .addTag("health", "Health check endpoints")
    .addTag("usernames", "Username management endpoints")
    .addTag("links", "Payment link validation and metadata endpoints")
    .addTag("transactions", "Stellar transaction and payment history")
    .addTag("scam-alerts", "Fraud detection and link scanning")
    .addTag(
      "analytics",
      "Dashboard analytics, time-series insights, and report exports",
    )
    .addTag("metrics", "Application performance and health metrics")
    .addTag("stellar", "Verified assets, path preview, Soroban preflight")
    .addTag("contracts", "Contract registry publication and discovery")
    .addTag(
      "developer",
      "Developer self-service: ping, webhook testing, key management, health score",
    )
    .build();

  return SwaggerModule.createDocument(app, swaggerConfig);
}
