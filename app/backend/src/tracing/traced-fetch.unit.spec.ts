import { SpanStatusCode } from '@opentelemetry/api';

import { withCorrelationId } from './correlation-baggage';
import { createTracedFetch } from './traced-fetch';
import { setupOtelTestHarness, type OtelTestHarness } from './test-support/otel-test-harness';

describe('createTracedFetch', () => {
  let harness: OtelTestHarness;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeAll(() => {
    harness = setupOtelTestHarness();
  });

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    harness.reset();
  });

  afterAll(async () => {
    await harness.teardown();
  });

  it('wraps a successful call in a db span named after the method and path', async () => {
    fetchSpy.mockResolvedValue(new Response('{}', { status: 200 }));
    const tracedFetch = createTracedFetch('db.supabase');

    const response = await tracedFetch('https://proj.supabase.co/rest/v1/usernames', {
      method: 'GET',
    });

    expect(response.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const [span] = harness.getFinishedSpans();
    expect(span.name).toBe('db.supabase GET /rest/v1/usernames');
    expect(span.attributes['db.system']).toBe('postgresql');
    expect(span.attributes['http.status_code']).toBe(200);
    expect(span.status.code).toBe(SpanStatusCode.UNSET);
  });

  it('marks the span as an error for a non-2xx response without throwing', async () => {
    fetchSpy.mockResolvedValue(new Response('not found', { status: 404 }));
    const tracedFetch = createTracedFetch('db.supabase');

    const response = await tracedFetch('https://proj.supabase.co/rest/v1/usernames');

    expect(response.status).toBe(404);
    const [span] = harness.getFinishedSpans();
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
  });

  it('records the exception and rethrows on network failure', async () => {
    fetchSpy.mockRejectedValue(new Error('network down'));
    const tracedFetch = createTracedFetch('db.supabase');

    await expect(
      tracedFetch('https://proj.supabase.co/rest/v1/usernames'),
    ).rejects.toThrow('network down');

    const [span] = harness.getFinishedSpans();
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
    expect(span.events.some((e) => e.name === 'exception')).toBe(true);
  });

  it('tags the span with the correlation id from baggage when present', async () => {
    fetchSpy.mockResolvedValue(new Response('{}', { status: 200 }));
    const tracedFetch = createTracedFetch('db.supabase');

    await withCorrelationId('req-db-1', () =>
      tracedFetch('https://proj.supabase.co/rest/v1/usernames'),
    );

    const [span] = harness.getFinishedSpans();
    expect(span.attributes.correlation_id).toBe('req-db-1');
  });
});
