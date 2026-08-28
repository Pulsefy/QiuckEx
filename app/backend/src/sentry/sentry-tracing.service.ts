/**
 * SentryTracingService
 *
 * Provides span-level performance instrumentation for QuickEx transaction
 * paths and their external dependencies (Horizon, Soroban RPC, cache).
 *
 * Usage (inject into services that call Horizon / Soroban / cache):
 *
 * ```typescript
 * const result = await this.tracing.traceHorizon('getPayments', () =>
 *   fetch(horizonUrl),
 * );
 * ```
 *
 * All traced calls appear as child spans inside the active Sentry transaction.
 * When no transaction is active (e.g. background jobs, tests) the callback is
 * executed transparently without any Sentry overhead.
 */

import { Injectable, Logger } from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';

/** Operation categories used in Sentry span `op` field. */
export const SpanOp = {
  TRANSACTION_COMPOSE: 'transaction.compose',
  TRANSACTION_SIMULATE: 'transaction.simulate',
  TRANSACTION_SUBMIT: 'transaction.submit',
  HORIZON: 'http.client.horizon',
  SOROBAN_RPC: 'rpc.soroban',
  CACHE: 'cache',
} as const;

export type SpanOpValue = (typeof SpanOp)[keyof typeof SpanOp];

@Injectable()
export class SentryTracingService {
  private readonly logger = new Logger(SentryTracingService.name);

  /**
   * Wrap a call to the Horizon API in a Sentry span.
   *
   * @param description  Short label for the span (e.g. "getPayments:accountId")
   * @param fn           Async function to execute inside the span
   */
  async traceHorizon<T>(description: string, fn: () => Promise<T>): Promise<T> {
    return this.trace(SpanOp.HORIZON, description, fn);
  }

  /**
   * Wrap a Soroban RPC call in a Sentry span.
   *
   * @param description  Short label (e.g. "simulateTransaction")
   * @param fn           Async function to trace
   */
  async traceSoroban<T>(description: string, fn: () => Promise<T>): Promise<T> {
    return this.trace(SpanOp.SOROBAN_RPC, description, fn);
  }

  /**
   * Wrap a cache read/write in a Sentry span.
   *
   * @param description  Short label (e.g. "get:payments:accountId")
   * @param fn           Async function to trace
   */
  async traceCache<T>(description: string, fn: () => Promise<T>): Promise<T> {
    return this.trace(SpanOp.CACHE, description, fn);
  }

  /**
   * Wrap a `compose` transaction path call in a Sentry span.
   */
  async traceCompose<T>(description: string, fn: () => Promise<T>): Promise<T> {
    return this.trace(SpanOp.TRANSACTION_COMPOSE, description, fn);
  }

  /**
   * Wrap a `simulate` transaction path call in a Sentry span.
   */
  async traceSimulate<T>(description: string, fn: () => Promise<T>): Promise<T> {
    return this.trace(SpanOp.TRANSACTION_SIMULATE, description, fn);
  }

  /**
   * Wrap a `submit` transaction path call in a Sentry span.
   */
  async traceSubmit<T>(description: string, fn: () => Promise<T>): Promise<T> {
    return this.trace(SpanOp.TRANSACTION_SUBMIT, description, fn);
  }

  /**
   * Generic span wrapper.  Falls back to plain execution when Sentry is not
   * initialised or there is no active transaction.
   */
  private async trace<T>(
    op: SpanOpValue,
    description: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    return Sentry.startSpan({ op, name: description }, async () => {
      try {
        return await fn();
      } catch (error) {
        this.logger.debug(`Sentry span [${op}:${description}] threw: ${(error as Error).message}`);
        throw error;
      }
    });
  }
}
