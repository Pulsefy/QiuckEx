import { trace, SpanStatusCode, type Attributes } from '@opentelemetry/api';

import { getCorrelationIdFromBaggage } from './correlation-baggage';

const tracer = trace.getTracer('quickex-backend-db');

/**
 * Wraps `fetch` with a DB span for every call, so a single change to the
 * Supabase client's `global.fetch` option instruments all PostgREST/RPC
 * calls the client makes, instead of hand-wrapping each repository method.
 * The underlying `fetch` call is still auto-instrumented by
 * `UndiciInstrumentation`, so this span nests a real network span.
 */
export function createTracedFetch(spanNamePrefix: string): typeof fetch {
  return async function tracedFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const method =
      init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : undefined) ?? 'GET';

    let path = url;
    try {
      path = new URL(url).pathname;
    } catch {
      // leave as the raw url if it isn't parseable
    }

    const attributes: Attributes = {
      'db.system': 'postgresql',
      'db.operation': method,
      'http.method': method,
      'url.path': path,
    };
    const correlationId = getCorrelationIdFromBaggage();
    if (correlationId) {
      attributes.correlation_id = correlationId;
    }

    return tracer.startActiveSpan(
      `${spanNamePrefix} ${method} ${path}`,
      { attributes },
      async (span) => {
        try {
          const response = await fetch(input, init);
          span.setAttribute('http.status_code', response.status);
          if (!response.ok) {
            span.setStatus({
              code: SpanStatusCode.ERROR,
              message: `HTTP ${response.status}`,
            });
          }
          return response;
        } catch (error) {
          span.recordException(error as Error);
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: error instanceof Error ? error.message : String(error),
          });
          throw error;
        } finally {
          span.end();
        }
      },
    );
  };
}
