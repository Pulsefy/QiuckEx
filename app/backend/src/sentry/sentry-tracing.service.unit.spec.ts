import { Test, TestingModule } from '@nestjs/testing';
import { SentryTracingService, SpanOp } from './sentry-tracing.service';
import * as Sentry from '@sentry/nestjs';

jest.mock('@sentry/nestjs', () => ({
  startSpan: jest.fn((opts, fn) => fn()),
}));

describe('SentryTracingService', () => {
  let service: SentryTracingService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SentryTracingService],
    }).compile();
    service = module.get(SentryTracingService);
  });

  afterEach(() => jest.clearAllMocks());

  it('traceHorizon executes the callback and returns its result', async () => {
    const result = await service.traceHorizon('test', async () => 42);
    expect(result).toBe(42);
    expect(Sentry.startSpan).toHaveBeenCalledWith(
      expect.objectContaining({ op: SpanOp.HORIZON }),
      expect.any(Function),
    );
  });

  it('traceSoroban executes the callback with SOROBAN_RPC op', async () => {
    await service.traceSoroban('simulateTransaction', async () => 'ok');
    expect(Sentry.startSpan).toHaveBeenCalledWith(
      expect.objectContaining({ op: SpanOp.SOROBAN_RPC }),
      expect.any(Function),
    );
  });

  it('traceCache executes the callback with CACHE op', async () => {
    await service.traceCache('get:payments', async () => null);
    expect(Sentry.startSpan).toHaveBeenCalledWith(
      expect.objectContaining({ op: SpanOp.CACHE }),
      expect.any(Function),
    );
  });

  it('traceCompose uses TRANSACTION_COMPOSE op', async () => {
    await service.traceCompose('compose:contract::method', async () => ({ success: true }));
    expect(Sentry.startSpan).toHaveBeenCalledWith(
      expect.objectContaining({ op: SpanOp.TRANSACTION_COMPOSE }),
      expect.any(Function),
    );
  });

  it('traceSimulate uses TRANSACTION_SIMULATE op', async () => {
    await service.traceSimulate('simulate:contract::method', async () => ({ success: true }));
    expect(Sentry.startSpan).toHaveBeenCalledWith(
      expect.objectContaining({ op: SpanOp.TRANSACTION_SIMULATE }),
      expect.any(Function),
    );
  });

  it('traceSubmit uses TRANSACTION_SUBMIT op', async () => {
    await service.traceSubmit('submit', async () => ({ success: true, hash: 'abc' }));
    expect(Sentry.startSpan).toHaveBeenCalledWith(
      expect.objectContaining({ op: SpanOp.TRANSACTION_SUBMIT }),
      expect.any(Function),
    );
  });

  it('propagates errors thrown by the callback', async () => {
    (Sentry.startSpan as jest.Mock).mockImplementation((_opts, fn) => fn());
    await expect(
      service.traceHorizon('failing', async () => {
        throw new Error('horizon down');
      }),
    ).rejects.toThrow('horizon down');
  });
});
