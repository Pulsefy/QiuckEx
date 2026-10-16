// OpenTelemetry MUST be imported before everything else so it can patch
// http/express/undici before those modules are required elsewhere.
import "./tracing/tracing";

// Sentry instrumentation MUST be imported before everything else
import "./sentry/instrument";

import "reflect-metadata";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { BadRequestException, Logger, ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { SwaggerModule } from "@nestjs/swagger";
import { createSwaggerDocument } from "./config/swagger.config";
import helmet from "helmet";

import { WinstonModule } from "nest-winston";
import { winstonConfig } from "./common/logging/winston.config";
import { LoggingInterceptor } from "./common/interceptors/logging.interceptor";
// ----------------------------------------

import { buildCorsOptions } from "./config/cors.config";
import { AppConfigService } from "./config";
import { AppModule } from "./app.module";
import { resolveNetworkSnapshot } from "./config/network.config";
import { GlobalHttpExceptionFilter } from "./common/filters/global-http-exception.filter";
import { mapValidationErrors } from "./common/utils/validation-error.mapper";
import { SentryExceptionFilter, SentryService } from "./sentry";
import { MetricsService } from "./metrics/metrics.service";
import { 
  sanitizeErrorMessage,
  createConfigSummary 
} from "./common/utils/redaction.util";

/**
 * Validates critical configuration at startup.
 * Fails fast if required settings are missing.
 */
function validateCriticalConfig(
  config: AppConfigService,
  logger: Logger,
): void {
  const errors: string[] = [];

  // Database is required
  if (!config.supabaseUrl) {
    errors.push('SUPABASE_URL is required');
  }
  if (!config.supabaseAnonKey) {
    errors.push('SUPABASE_ANON_KEY is required');
  }

  // Network is required
  if (!config.network) {
    errors.push('NETWORK is required (must be "testnet" or "mainnet")');
  }

  try {
    resolveNetworkSnapshot();
  } catch (error) {
    errors.push(`Network config invalid: ${(error as Error).message}`);
  }

  // If there are critical errors, fail fast
  if (errors.length > 0) {
    const errorMessage = `Critical configuration errors:\n${errors.map(e => `  - ${e}`).join('\n')}`;
    logger.error(errorMessage);
    throw new Error(sanitizeErrorMessage(errorMessage));
  }

  // Log warnings for optional but important configurations
  if (!config.isPaymentSigningConfigured) {
    logger.warn('STELLAR_SECRET_KEY not configured - payment signing disabled (read-only mode)');
  }

  logger.log('Critical configuration validated successfully');
}

async function bootstrap() {
  const logger = new Logger("Bootstrap");

  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    rawBody: true, // Required for GitHub webhook HMAC signature verification
  });

  const configService = app.get(AppConfigService);

  // Validate critical configuration at startup
  validateCriticalConfig(configService, logger);

  // Log configuration summary (safe, no secrets)
  const envSummary = createConfigSummary({
    SUPABASE_URL: configService.supabaseUrl,
    SUPABASE_ANON_KEY: configService.supabaseAnonKey,
    NETWORK: configService.network,
    HORIZON_URL: configService.horizonUrl,
    SOROBAN_RPC_URL: configService.sorobanRpcUrl,
    STELLAR_EXPLORER_URL: configService.stellarExplorerUrl,
    STELLAR_SECRET_KEY: configService.stellarSecretKey,
    STELLAR_PUBLIC_KEY: configService.stellarPublicKey,
  });
  logger.log(envSummary);
  const networkSnapshot = resolveNetworkSnapshot();
  logger.log(
    `Active network: ${networkSnapshot.network} (${networkSnapshot.passphrase}); horizon=${networkSnapshot.horizonUrl}; soroban=${networkSnapshot.sorobanRpcUrl}; explorer=${networkSnapshot.explorerUrl}`,
  );

  // Use Helmet for security headers
  app.use(helmet());

  app.enableCors(
    buildCorsOptions({
      nodeEnv: configService.nodeEnv,
      allowedOrigins: configService.corsAllowedOrigins,
      vercelProject: configService.corsVercelProject,
    }),
  );

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

  // Register Sentry exception filter FIRST so it captures errors,
  // then the existing HTTP exception filter handles the response.
  const sentryService = app.get(SentryService);
  const metricsService = app.get(MetricsService);
  app.useGlobalFilters(
    new SentryExceptionFilter(sentryService, configService),
    new GlobalHttpExceptionFilter(configService, metricsService),
  );

  // Swagger setup
  const document = createSwaggerDocument(app, configService.network);
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
