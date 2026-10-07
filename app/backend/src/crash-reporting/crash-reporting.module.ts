import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { CrashReportingService } from './crash-reporting.service';
import { CrashReportingController } from './crash-reporting.controller';
import { CrashReportingAdminController } from './crash-reporting-admin.controller';
import { CrashReportingRepository } from './crash-reporting.repository';
import { RedactionService } from './redaction.service';
import { SupabaseModule } from '../supabase/supabase.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { LogCaptureInterceptor } from './log-capture.interceptor';
import { LogCaptureMiddleware } from './log-capture.middleware';

/**
 * Module for crash reporting and log capture with strict redaction
 *
 * #1063: LogCaptureMiddleware opens a separate log buffer for every request
 * and LogCaptureInterceptor (registered globally here) writes into it, so
 * crash reports and log exports only ever contain the requesting user's own
 * lines.
 */
@Module({
  imports: [SupabaseModule, ApiKeysModule],
  controllers: [CrashReportingController, CrashReportingAdminController],
  providers: [
    CrashReportingService,
    CrashReportingRepository,
    RedactionService,
    {
      provide: APP_INTERCEPTOR,
      useClass: LogCaptureInterceptor,
    },
  ],
  exports: [CrashReportingService, RedactionService],
})
export class CrashReportingModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(LogCaptureMiddleware).forRoutes('*');
  }
}
