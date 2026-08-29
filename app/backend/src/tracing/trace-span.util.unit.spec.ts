import { SpanStatusCode } from '@opentelemetry/api';

import { withCorrelationId } from './correlation-baggage';
import { withSpan } from './trace-span.util';
import { setupOtelTestHarness, type OtelTestHarness } from './test-support/otel-test-harness';

describe('withSpan', () => {
  let harness: OtelTestHarness;

  beforeAll(() => {
    harness = setupOtelTestHarness();
  });

  afterEach(() => {
    harness.reset();
  });

  afterAll(async () => {
    await harness.teardown();
  });

  it('creates a span with the given name and attributes, and resolves with the callback result', async () => {
    const result = await withSpan(
      'soroban_rpc.getAccount',
      { 'rpc.system': 'soroban-rpc' },
      async () => 'ok',
    );

    expect(result).toBe('ok');
    const [span] = harness.getFinishedSpans();
    expect(span.name).toBe('soroban_rpc.getAccount');
    expect(span.attributes['rpc.system']).toBe('soroban-rpc');
    expect(span.status.code).toBe(SpanStatusCode.UNSET);
  });

  it('tags the span with the correlation id from baggage when present', async () => {
    await withCorrelationId('req-abc', () =>
      withSpan('horizon.getAccount', {}, async () => 'ok'),
    );

    const [span] = harness.getFinishedSpans();
    expect(span.attributes.correlation_id).toBe('req-abc');
  });

  it('omits correlation_id when none is on the context', async () => {
    await withSpan('horizon.getAccount', {}, async () => 'ok');

    const [span] = harness.getFinishedSpans();
    expect(span.attributes.correlation_id).toBeUndefined();
  });

  it('records the exception, sets an ERROR status, ends the span, and rethrows', async () => {
    const boom = new Error('rpc unreachable');

    await expect(
      withSpan('soroban_rpc.getAccount', {}, async () => {
        throw boom;
      }),
    ).rejects.toThrow('rpc unreachable');

    const [span] = harness.getFinishedSpans();
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
    expect(span.status.message).toBe('rpc unreachable');
    expect(span.events.some((e) => e.name === 'exception')).toBe(true);
    expect(span.ended).toBe(true);
  });

  it('gives the callback the active span so it can add its own attributes/events', async () => {
    await withSpan('horizon.getAccount', {}, async (span) => {
      span.setAttribute('http.status_code', 200);
    });

    const [span] = harness.getFinishedSpans();
    expect(span.attributes['http.status_code']).toBe(200);
  });
});
