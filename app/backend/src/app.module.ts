import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';

import { AppConfigModule } from './config';
import { HealthModule } from './health/health.module';
import { SupabaseModule } from './supabase/supabase.module';
import { UsernamesModule } from './usernames/usernames.module';
import { LinksModule } from './links/links.module';
import { NotificationService } from './notifications/notification.service';
import { ScamAlertsModule } from "./scam-alerts/scam-alerts.module";

@Module({
  imports: [
    EventEmitterModule.forRoot({
      wildcard: true,
      delimiter: '.',
    }),
    AppConfigModule, 
    SupabaseModule, 
    HealthModule, 
    UsernamesModule,
    LinksModule,
    ScamAlertsModule,
    
  ],
  providers: [NotificationService],
})
export class AppModule {}