export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerOptions {
  /** Number of failures within `windowMs` required to open the circuit. */
  failureThreshold?: number;
  /** Sliding window (ms) over which failures are counted. */
  windowMs?: number;
  /** Time (ms) the circuit stays open before a half-open probe is allowed. */
  openTimeoutMs?: number;
  /** Frequency (ms) at which half-open probes are attempted. */
  probeIntervalMs?: number;
  /** Number of consecutive successes needed (while half-open) to reset. */
  successThreshold?: number;
  /** Optional clock injection for tests. */
  now?: () => number;
}

/**
 * Stateful circuit breaker.
 *
 * - CLOSED   : requests flow; tracks failures over a sliding 60s window.
 * - OPEN     : requests are short-circuited after `failureThreshold` failures;
 *              a half-open probe is permitted every `probeIntervalMs`.
 * - HALF_OPEN: a limited probe of requests is allowed; a success resets the
 *              circuit to CLOSED, a failure re-opens it.
 */
export class CircuitBreaker {
  private state: CircuitState = "closed";
  private readonly failureThreshold: number;
  private readonly windowMs: number;
  private readonly openTimeoutMs: number;
  private readonly probeIntervalMs: number;
  private readonly successThreshold: number;
  private readonly now: () => number;

  private failures: number[] = [];
  private consecutiveSuccesses = 0;
  private lastOpenedAt = 0;
  private lastProbeAt = 0;
  private transitionCount = 0;

  constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? 5;
    this.windowMs = options.windowMs ?? 60_000;
    this.openTimeoutMs = options.openTimeoutMs ?? 30_000;
    this.probeIntervalMs = options.probeIntervalMs ?? 30_000;
    this.successThreshold = options.successThreshold ?? 1;
    this.now = options.now ?? (() => Date.now());
  }

  /**
   * Returns true if a call is allowed to reach the remote service.
   */
  isAllowed(): boolean {
    const now = this.now();
    switch (this.state) {
      case "closed":
        return true;
      case "open":
        // Allow a half-open probe once the open timeout has elapsed and
        // enough time since the last probe has passed.
        if (
          now - this.lastOpenedAt >= this.openTimeoutMs &&
          now - this.lastProbeAt >= this.probeIntervalMs
        ) {
          this.setState("half_open");
          this.lastProbeAt = now;
          return true;
        }
        return false;
      case "half_open":
        return true;
      default:
        return true;
    }
  }

  onSuccess(): void {
    this.failures = [];
    if (this.state === "half_open") {
      this.consecutiveSuccesses += 1;
      if (this.consecutiveSuccesses >= this.successThreshold) {
        // Reset to closed after a successful probe.
        this.setState("closed");
        this.consecutiveSuccesses = 0;
      }
    } else if (this.state === "closed") {
      this.consecutiveSuccesses = 0;
    }
  }

  onFailure(): void {
    const now = this.now();
    if (this.state === "half_open") {
      // A failure during a probe re-opens the circuit.
      this.setState("open");
      this.lastOpenedAt = now;
      this.consecutiveSuccesses = 0;
      return;
    }

    if (this.state !== "closed") return;

    this.failures.push(now);
    this.failures = this.failures.filter((t) => t > now - this.windowMs);

    if (this.failures.length >= this.failureThreshold) {
      this.setState("open");
      this.lastOpenedAt = now;
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  getStats() {
    const now = this.now();
    this.failures = this.failures.filter((t) => t > now - this.windowMs);
    return {
      state: this.state,
      failuresInWindow: this.failures.length,
      failureThreshold: this.failureThreshold,
      windowMs: this.windowMs,
      openTimeoutMs: this.openTimeoutMs,
      probeIntervalMs: this.probeIntervalMs,
      transitionCount: this.transitionCount,
    };
  }

  reset(): void {
    this.failures = [];
    this.consecutiveSuccesses = 0;
    this.lastOpenedAt = 0;
    this.lastProbeAt = 0;
    this.setState("closed");
  }

  private setState(next: CircuitState): void {
    if (next !== this.state) {
      this.state = next;
      this.transitionCount += 1;
    }
  }
}
