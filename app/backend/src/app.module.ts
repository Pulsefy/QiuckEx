import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';

import { AppConfigModule } from './config';
import { HealthModule } from './health/health.module';
import { SupabaseModule } from './supabase/supabase.module';
import { UsernamesModule } from './usernames/usernames.module';
import { NotificationService } from './notifications/notification.service';

@Module({
  imports: [
    EventEmitterModule.forRoot({
      wildcard: true,
      delimiter: '.',
    }),
    AppConfigModule, 
    SupabaseModule, 
    HealthModule, 
    UsernamesModule
  ],
  providers: [NotificationService],
})
export class AppModule {}