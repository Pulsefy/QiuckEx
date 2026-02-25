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

  
  const allowedOrigins = [
    "http://localhost:3000",
    "https://app.quickex.example.com", 
  ];

  // Use Helmet for security headers
  app.use(helmet());
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
    allowedHeaders: ["Content-Type", "Authorization", "x-correlation-id"], 
  });

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
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup("docs", app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  const port = configService.port;
  await app.listen(port);

  logger.log(`Backend listening on http://localhost:${port}`);
  logger.log(`Swagger docs available at http://localhost:${port}/docs`);
}

void bootstrap();
