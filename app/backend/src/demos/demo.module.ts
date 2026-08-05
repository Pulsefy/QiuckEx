import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { SupabaseModule } from '../supabase/supabase.module';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { DemoController } from './demo.controller';
import { DemoService } from './demo.service';
import { SeedResetController } from './seed-reset.controller';
import { SeedResetScheduler } from './seed-reset.scheduler';
import { SeedResetHandler } from '../job-queue/handlers/seed-reset.handler';

@Module({
  imports: [
    ApiKeysModule,
    ConfigModule,
    SupabaseModule,
    EventEmitterModule,
    JobQueueModule,
  ],
  controllers: [
    DemoController,
    SeedResetController,
  ],
  providers: [
    DemoService,
    ApiKeyGuard,
    SeedResetScheduler,
    SeedResetHandler,
  ],
  exports: [
    DemoService,
    SeedResetScheduler,
  ],
})
export class DemoModule {}