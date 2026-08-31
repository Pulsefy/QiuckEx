import { context, propagation } from '@opentelemetry/api';

/**
 * Carries the existing request correlation id through OpenTelemetry's async
 * context (the same AsyncLocalStorage-backed mechanism spans use), so
 * services that never receive `req` directly — Soroban RPC, Horizon, the
 * Supabase client — can still tag their spans with it.
 */
export const CORRELATION_BAGGAGE_KEY = 'correlation_id';

export function withCorrelationId<T>(correlationId: string, fn: () => T): T {
  const baggage = propagation.createBaggage({
    [CORRELATION_BAGGAGE_KEY]: { value: correlationId },
  });
  const ctx = propagation.setBaggage(context.active(), baggage);
  return context.with(ctx, fn);
}

export function getCorrelationIdFromBaggage(): string | undefined {
  return propagation
    .getBaggage(context.active())
    ?.getEntry(CORRELATION_BAGGAGE_KEY)?.value;
}
