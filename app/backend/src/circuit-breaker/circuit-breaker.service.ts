import { Injectable, Logger } from "@nestjs/common";
import { CircuitBreaker, CircuitBreakerOptions, CircuitState } from "./circuit-breaker";
import { MetricsService } from "../metrics/metrics.service";

@Injectable()
export class CircuitBreakerService {
  private readonly logger = new Logger(CircuitBreakerService.name);
  private readonly breakers = new Map<string, CircuitBreaker>();

  constructor(private readonly metricsService: MetricsService) {}

  /**
   * Get (or lazily create) a named circuit breaker.
   */
  getOrCreate(name: string, options: CircuitBreakerOptions = {}): CircuitBreaker {
    let breaker = this.breakers.get(name);
    if (!breaker) {
      breaker = new CircuitBreaker(options);
      this.breakers.set(name, breaker);
      this.logger.log(`Circuit breaker '${name}' created (${breaker.getState()})`);
    }
    return breaker;
  }

  /**
   * Convenience accessor for the Horizon API circuit.
   */
  get horizon(): CircuitBreaker {
    return this.getOrCreate("horizon", {
      failureThreshold: 5,
      windowMs: 60_000,
      openTimeoutMs: 30_000,
      probeIntervalMs: 30_000,
      successThreshold: 1,
    });
  }

  /**
   * Records the current state of every known breaker as a metric so it is
   * observable in Prometheus and reports.
   */
  snapshotMetrics(): void {
    for (const [name, breaker] of this.breakers.entries()) {
      const state = breaker.getState();
      this.metricsService.setCircuitBreakerState(name, state);
      // Increment a transition counter every time states change.
      const stats = breaker.getStats();
      this.metricsService.setCircuitBreakerTransitions(
        name,
        stats.transitionCount,
      );
    }
  }

  /**
   * Human-readable report for admin health endpoints.
   */
  getReport(): Array<{
    name: string;
    state: CircuitState;
    failuresInWindow: number;
    failureThreshold: number;
  }> {
    return [...this.breakers.entries()].map(([name, breaker]) => {
      const stats = breaker.getStats();
      return {
        name,
        state: stats.state,
        failuresInWindow: stats.failuresInWindow,
        failureThreshold: stats.failureThreshold,
      };
    });
  }
}
