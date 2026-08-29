import type { Request, Response } from 'express';
import { trace } from '@opentelemetry/api';

import { getCorrelationIdFromBaggage } from '../../tracing/correlation-baggage';
import {
  setupOtelTestHarness,
  type OtelTestHarness,
} from '../../tracing/test-support/otel-test-harness';
import { CorrelationIdMiddleware } from './correlation-id.middleware';

jest.mock('uuid', () => ({ v4: () => 'generated-uuid' }));

function createRequest(headers: Record<string, string> = {}): Request {
  return {
    header: (name: string) => headers[name.toLowerCase()],
  } as unknown as Request;
}

function createResponse(): Response {
  const headers: Record<string, string> = {};
  return {
    setHeader: (name: string, value: string) => {
      headers[name] = value;
    },
    getHeader: (name: string) => headers[name],
  } as unknown as Response;
}

describe('CorrelationIdMiddleware', () => {
  let harness: OtelTestHarness;
  let middleware: CorrelationIdMiddleware;

  beforeAll(() => {
    harness = setupOtelTestHarness();
  });

  afterEach(() => {
    harness.reset();
  });

  afterAll(async () => {
    await harness.teardown();
  });

  beforeEach(() => {
    middleware = new CorrelationIdMiddleware();
  });

  it('generates a correlation id and attaches it to the request and response headers', () => {
    const req = createRequest();
    const res = createResponse();
    const next = jest.fn();

    middleware.use(req, res, next);

    expect((req as unknown as { correlationId: string }).correlationId).toBe(
      'generated-uuid',
    );
    expect(res.getHeader('x-request-id')).toBe('generated-uuid');
    expect(res.getHeader('x-correlation-id')).toBe('generated-uuid');
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('reuses an inbound x-request-id header instead of generating a new id', () => {
    const req = createRequest({ 'x-request-id': 'client-supplied-id' });
    const res = createResponse();
    const next = jest.fn();

    middleware.use(req, res, next);

    expect((req as unknown as { correlationId: string }).correlationId).toBe(
      'client-supplied-id',
    );
  });

  it('makes the correlation id readable via OTel baggage inside next()', () => {
    const req = createRequest({ 'x-request-id': 'req-otel-1' });
    const res = createResponse();
    let seenInsideNext: string | undefined;

    middleware.use(req, res, () => {
      seenInsideNext = getCorrelationIdFromBaggage();
    });

    expect(seenInsideNext).toBe('req-otel-1');
  });

  it('tags the active span with the correlation id, joining logs and traces', () => {
    const req = createRequest({ 'x-request-id': 'req-otel-2' });
    const res = createResponse();

    trace.getTracer('test').startActiveSpan('http.request', (span) => {
      middleware.use(req, res, () => undefined);
      span.end();
    });

    const [span] = harness.getFinishedSpans();
    expect(span.attributes.correlation_id).toBe('req-otel-2');
  });
});
