/**
 * Export Storage Module – BE-102
 *
 * Provides ExportStorageService and the nightly retention scheduler.
 */

import { Module } from '@nestjs/common';
import { ExportStorageService } from './export-storage.service';
import { ExportRetentionScheduler } from './export-retention.scheduler';
import { SupabaseModule } from '../supabase/supabase.module';

@Module({
  imports: [SupabaseModule],
  providers: [ExportStorageService, ExportRetentionScheduler],
  exports: [ExportStorageService],
})
export class ExportStorageModule {}
