/**
 * Exports Module
 *
 * Provides endpoints for requesting data exports and redeeming
 * signed download links (BE-102).
 */

import { Module } from '@nestjs/common';
import { ExportsController } from './exports.controller';
import { ExportStorageModule } from './export-storage.module';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';

@Module({
  imports: [JobQueueModule, ApiKeysModule, ExportStorageModule],
  controllers: [ExportsController],
})
export class ExportsModule {}
