/**
 * Exports Module
 * 
 * Provides endpoints for requesting data exports.
 */

import { Module } from '@nestjs/common';
import { ExportsController } from './exports.controller';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';

@Module({
  imports: [JobQueueModule, ApiKeysModule],
  controllers: [ExportsController],
})
export class ExportsModule {}
