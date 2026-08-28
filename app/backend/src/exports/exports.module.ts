import { Module } from '@nestjs/common';
import { ExportsController } from './exports.controller';
import { ExportsService } from './exports.service';
import { ExportStorageModule } from './export-storage.module';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';

@Module({
  imports: [JobQueueModule, ApiKeysModule, ExportStorageModule],
  controllers: [ExportsController],
  providers: [ExportsService],
  exports: [ExportsService],
})
export class ExportsModule {}
