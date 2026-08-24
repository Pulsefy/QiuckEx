/**
 * Exports Module
 * 
 * Provides endpoints for requesting data exports.
 */

import { Module, forwardRef } from '@nestjs/common';
import { ExportsController } from './exports.controller';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { ExportsService } from './exports.service';

@Module({
  imports: [
    forwardRef(() => JobQueueModule),
    ApiKeysModule,
    SupabaseModule,
  ],
  controllers: [ExportsController],
  providers: [ExportsService],
  exports: [ExportsService],
})
export class ExportsModule {}
