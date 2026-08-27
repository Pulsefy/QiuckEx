import { Global, Module } from "@nestjs/common";
import { MetricsModule } from "../metrics/metrics.module";
import { CircuitBreakerService } from "./circuit-breaker.service";

/**
 * Global circuit-breaker registry for external API calls (e.g. Horizon).
 * Provides named CircuitBreaker instances and snapshots their state to
 * Prometheus metrics.
 */
@Global()
@Module({
  imports: [MetricsModule],
  providers: [CircuitBreakerService],
  exports: [CircuitBreakerService],
})
export class CircuitBreakerModule {}
