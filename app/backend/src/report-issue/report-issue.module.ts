import { Module } from '@nestjs/common';
import { ReportIssueService } from './report-issue.service';
import { ReportIssueController } from './report-issue.controller';
import { ReportIssueRepository } from './report-issue.repository';
import { SupabaseModule } from '../supabase/supabase.module';
import { CrashReportingModule } from '../crash-reporting/crash-reporting.module';

/**
 * Module for issue report submission and retrieval with redaction and abuse prevention
 */
@Module({
  imports: [SupabaseModule, CrashReportingModule],
  controllers: [ReportIssueController],
  providers: [
    ReportIssueService,
    ReportIssueRepository,
  ],
  exports: [ReportIssueService],
})
export class ReportIssueModule {}
