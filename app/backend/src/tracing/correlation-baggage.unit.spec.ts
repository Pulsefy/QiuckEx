import {
  getCorrelationIdFromBaggage,
  withCorrelationId,
} from './correlation-baggage';
import { setupOtelTestHarness, type OtelTestHarness } from './test-support/otel-test-harness';

describe('correlation id baggage propagation', () => {
  let harness: OtelTestHarness;

  beforeAll(() => {
    harness = setupOtelTestHarness();
  });

  afterAll(async () => {
    await harness.teardown();
  });

  it('returns undefined outside of any correlation id context', () => {
    expect(getCorrelationIdFromBaggage()).toBeUndefined();
  });

  it('makes the correlation id readable inside withCorrelationId', () => {
    withCorrelationId('req-123', () => {
      expect(getCorrelationIdFromBaggage()).toBe('req-123');
    });
  });

  it('propagates across async continuations started inside the callback', async () => {
    await withCorrelationId('req-456', async () => {
      await Promise.resolve();
      expect(getCorrelationIdFromBaggage()).toBe('req-456');
    });
  });

  it('does not leak the correlation id outside of the callback', () => {
    withCorrelationId('req-789', () => {
      // no-op
    });
    expect(getCorrelationIdFromBaggage()).toBeUndefined();
  });

  it('supports nested correlation ids, restoring the outer one after the inner scope ends', () => {
    withCorrelationId('outer', () => {
      expect(getCorrelationIdFromBaggage()).toBe('outer');
      withCorrelationId('inner', () => {
        expect(getCorrelationIdFromBaggage()).toBe('inner');
      });
      expect(getCorrelationIdFromBaggage()).toBe('outer');
    });
  });
});
