import {
  Module,
  MiddlewareConsumer,
  NestModule,
  Type,
  DynamicModule,
  ForwardReference,
} from "@nestjs/common";
import { EventEmitterModule } from "@nestjs/event-emitter";
import { ThrottlerModule } from "@nestjs/throttler";
import { ScheduleModule } from "@nestjs/schedule";
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
import { PaymentsModule } from "./payments/payments.module";
import { ReconciliationModule } from "./reconciliation/reconciliation.module";
import { MetricsMiddleware } from "./metrics/metrics.middleware";
import { MetricsInterceptor } from "./metrics/metrics.interceptor";
import { CorrelationIdMiddleware } from "./common/middleware/correlation-id.middleware";
import { NotificationsModule } from "./notifications/notifications.module";
import { IngestionModule } from "./ingestion/ingestion.module";
import { ApiKeysModule } from "./api-keys/api-keys.module";

type AppImport =
  | Type<unknown>
  | DynamicModule
  | Promise<DynamicModule>
  | ForwardReference<unknown>;

@Module({
  imports: ((): AppImport[] => {
    const baseImports: AppImport[] = [
      AppConfigModule,
      // ScheduleModule registered once here — shared by NotificationsModule and ReconciliationModule
      ScheduleModule.forRoot(),
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
      PaymentsModule,
      IngestionModule,
      ApiKeysModule,
    ];

    // In development, if SUPABASE_URL points to a localhost placeholder (i.e. you don't
    // have a running Supabase instance), skip loading the Reconciliation module which
    // interacts with Supabase and runs scheduled jobs. This avoids noisy network errors
    // during local development and recording sessions.
    try {
      const supabaseUrl = process.env.SUPABASE_URL ?? "";
      const isLocalSupabase =
        supabaseUrl.includes("localhost") || supabaseUrl.includes("127.0.0.1");

      // Only load Reconciliation & Notifications modules when Supabase is real/reachable.
      if (!isLocalSupabase) {
        baseImports.push(ReconciliationModule as AppImport);
        baseImports.push(NotificationsModule as AppImport);
      } else {
        // eslint-disable-next-line no-console
        console.log(
          "Skipping Reconciliation & Notifications modules in dev (local Supabase)",
        );
      }
    } catch (e) {
      // If anything goes wrong, default to including the modules.
      baseImports.push(ReconciliationModule as AppImport);
      baseImports.push(NotificationsModule as AppImport);
    }
    return baseImports;
  })(),
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: MetricsInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(MetricsMiddleware, CorrelationIdMiddleware).forRoutes("*");
  }
}
