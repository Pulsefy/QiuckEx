import "reflect-metadata";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { BadRequestException, Logger, ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core"; //installed
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import helmet from "helmet";

import { WinstonModule } from "nest-winston";
import { winstonConfig } from "./common/logging/winston.config";
import { LoggingInterceptor } from "./common/interceptors/logging.interceptor";
// ----------------------------------------

import { AppModule } from "./app.module";
import { AppConfigService } from "./config";
import { GlobalHttpExceptionFilter } from "./common/filters/global-http-exception.filter";
import { mapValidationErrors } from "./common/utils/validation-error.mapper";

async function bootstrap() {
  const logger = new Logger("Bootstrap");

  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
  });

  const configService = app.get(AppConfigService);

  // Use Helmet for security headers
  app.use(helmet());

  // In development allow all origins to make it easy to test from Expo web or devices on LAN.
  // In production keep the stricter origin whitelist to avoid accidental exposure.
  if (process.env.NODE_ENV !== "production") {
    app.enableCors();
    logger.log("CORS enabled for all origins (dev mode)");
  } else {
    const allowedOrigins = [
      "http://localhost:3000",
      "https://app.quickex.example.com",
    ];

    app.enableCors({
      origin: (origin, callback) => {
        if (!origin) {
          return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          logger.warn(`CORS blocked request from origin: ${origin}`);
          callback(new Error(`Origin not allowed by CORS: ${origin}`));
        }
      },
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "x-correlation-id",
        "X-API-Key",
      ],

    });
  }

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) => {
        const mapped = mapValidationErrors(errors);
        return new BadRequestException({
          code: "VALIDATION_ERROR",
          message: mapped.message,
          fields: mapped.fields,
        });
      },
    }),
  );

  app.useGlobalInterceptors(new LoggingInterceptor());

  app.useGlobalFilters(new GlobalHttpExceptionFilter(configService));

  // Swagger setup
  const swaggerConfig = new DocumentBuilder()
    .setTitle("QuickEx Backend")
    .setDescription(
      "QuickEx API documentation - A Stellar-based exchange platform. " +
        `Currently connected to: ${configService.network}`,
    )
    .setVersion("v1")
    .addTag("health", "Health check endpoints")
    .addTag("usernames", "Username management endpoints")
    .addTag("links", "Payment link validation and metadata endpoints")
    .addTag("transactions", "Stellar transaction and payment history")
    .addTag("scam-alerts", "Fraud detection and link scanning")
    .addTag("metrics", "Application performance and health metrics")
    .addTag("stellar", "Verified assets, path preview, Soroban preflight")
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup("docs", app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  const port = configService.port;
  // Bind to 0.0.0.0 so devices on your LAN can access the dev server.
  await app.listen(port, "0.0.0.0");

  logger.log(`Backend listening on http://0.0.0.0:${port}`);
  logger.log(`Swagger docs available at http://localhost:${port}/docs`);
}

void bootstrap();
