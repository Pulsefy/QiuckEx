import { trace, SpanStatusCode, type Attributes, type Span } from '@opentelemetry/api';

import { getCorrelationIdFromBaggage } from './correlation-baggage';

const tracer = trace.getTracer('quickex-backend');

/**
 * Runs `fn` inside a new active span named `name`, tagging it with the
 * request's correlation id (if any is on the current context) so traces and
 * correlation-id-keyed logs can be joined. Records exceptions and always
 * ends the span.
 */
export async function withSpan<T>(
  name: string,
  attributes: Attributes,
  fn: (span: Span) => Promise<T>,
): Promise<T> {
  const correlationId = getCorrelationIdFromBaggage();
  const mergedAttributes: Attributes = correlationId
    ? { ...attributes, correlation_id: correlationId }
    : attributes;

  return tracer.startActiveSpan(name, { attributes: mergedAttributes }, async (span) => {
    try {
      return await fn(span);
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
  });
}
