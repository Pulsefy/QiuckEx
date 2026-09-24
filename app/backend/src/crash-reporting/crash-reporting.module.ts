import { Module } from '@nestjs/common';
import { CrashReportingService } from './crash-reporting.service';
import { CrashReportingController } from './crash-reporting.controller';
import { CrashReportingAdminController } from './crash-reporting-admin.controller';
import { CrashReportingRepository } from './crash-reporting.repository';
import { RedactionService } from './redaction.service';
import { SupabaseModule } from '../supabase/supabase.module';

/**
 * Module for crash reporting and log capture with strict redaction
 */
@Module({
  imports: [SupabaseModule],
  controllers: [CrashReportingController, CrashReportingAdminController],
  providers: [
    CrashReportingService,
    CrashReportingRepository,
    RedactionService,
  ],
  exports: [CrashReportingService, RedactionService],
})
export class CrashReportingModule {}
