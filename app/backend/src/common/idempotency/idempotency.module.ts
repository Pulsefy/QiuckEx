import { Module } from "@nestjs/common";

import { AppConfigModule } from "../../config";
import { IdempotencyInterceptor } from "./idempotency.interceptor";
import { IdempotencyStore } from "./idempotency-store.service";

/**
 * Provides `Idempotency-Key` support for mutating payment and link
 * endpoints (BE-109). Import this module in any module whose controllers
 * apply `IdempotencyInterceptor`.
 */
@Module({
  imports: [AppConfigModule],
  providers: [IdempotencyStore, IdempotencyInterceptor],
  exports: [IdempotencyStore, IdempotencyInterceptor],
})
export class IdempotencyModule {}
