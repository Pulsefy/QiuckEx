import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { AppConfigService } from './app-config.service';
import { envSchema } from './env.schema';

/**
 * Global configuration module.
 * Validates environment variables at startup using Joi schema.
 * Provides typed AppConfigService for accessing configuration values.
 */
@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: envSchema,
      validationOptions: {
        abortEarly: false, // Report all validation errors, not just the first
        allowUnknown: true, // Allow unknown environment variables
      },
    }),
  ],
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class AppConfigModule {}
