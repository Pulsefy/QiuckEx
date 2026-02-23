import { Module, MiddlewareConsumer, NestModule } from "@nestjs/common";
import { EventEmitterModule } from "@nestjs/event-emitter";
import { ThrottlerModule } from "@nestjs/throttler";
import { APP_INTERCEPTOR } from "@nestjs/core";

import { AppConfigModule } from "./config";
import { HealthModule } from "./health/health.module";
import { StellarModule } from "./stellar/stellar.module";
import { SupabaseModule } from "./supabase/supabase.module";
import { UsernamesModule } from "./usernames/usernames.module";
import { MetricsModule } from "./metrics/metrics.module";
import { LinksModule } from "./links/links.module";
import { ScamAlertsModule } from "./scam-alerts/scam-alerts.module";
import { TransactionsModule } from "./transactions/transactions.module";
import { MetricsMiddleware } from "./metrics/metrics.middleware";
import { MetricsInterceptor } from "./metrics/metrics.interceptor";


import { CorrelationIdMiddleware } from "./common/middleware/correlation-id.middleware";

@Module({
  imports: [
    AppConfigModule,
    EventEmitterModule.forRoot({
      wildcard: true,
      delimiter: ".",
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 20,
      },
    ]),
    SupabaseModule,
    HealthModule,
    StellarModule,
    UsernamesModule,
    MetricsModule,
    LinksModule,
    ScamAlertsModule,
    TransactionsModule,
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: MetricsInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    
    consumer
      .apply(MetricsMiddleware, CorrelationIdMiddleware)
      .forRoutes("*");
  }
}