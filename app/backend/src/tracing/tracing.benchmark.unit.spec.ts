/**
 * Benchmark backing the BE-113 acceptance criterion: "Sampling defaults keep
 * overhead acceptable under load, verified by a benchmark."
 *
 * This exercises the real sampler classes and the real shipped default
 * (resolveOtelConfig's sampleRate) against an in-memory exporter — no
 * network I/O, no global http/express patching — so it's safe to run as
 * part of the regular Jest unit suite instead of a one-off script.
 */
import { context, type Tracer } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  ParentBasedSampler,
  SimpleSpanProcessor,
  TraceIdRatioBasedSampler,
} from '@opentelemetry/sdk-trace-base';

import { resolveOtelConfig } from './otel.config';

const ITERATIONS = 1000;

// Stand-ins for the real RPC/Horizon/DB network calls: the benchmark isolates
// tracing overhead, not I/O latency, so these are trivial async no-ops.
const simulatedRpcCall = () => Promise.resolve();
const simulatedHorizonCall = () => Promise.resolve();
const simulatedDbCall = () => Promise.resolve();

async function simulateTracedRequest(tracer: Tracer | undefined): Promise<void> {
  if (!tracer) {
    // What withSpan()'s callers do when tracing is disabled: just run.
    await simulatedRpcCall();
    await simulatedHorizonCall();
    await simulatedDbCall();
    return;
  }

  await tracer.startActiveSpan('http.request', async (root) => {
    try {
      await tracer.startActiveSpan('soroban_rpc.getAccount', async (span) => {
        try {
          await simulatedRpcCall();
        } finally {
          span.end();
        }
      });
      await tracer.startActiveSpan('horizon.getAccount', async (span) => {
        try {
          await simulatedHorizonCall();
        } finally {
          span.end();
        }
      });
      await tracer.startActiveSpan('db.supabase GET /rest/v1/usernames', async (span) => {
        try {
          await simulatedDbCall();
        } finally {
          span.end();
        }
      });
    } finally {
      root.end();
    }
  });
}

async function timeIterations(tracer: Tracer | undefined, iterations: number): Promise<number> {
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i += 1) {
    await simulateTracedRequest(tracer);
  }
  const end = process.hrtime.bigint();
  return Number(end - start) / 1_000_000; // ms
}

describe('tracing overhead benchmark', () => {
  let contextManager: AsyncLocalStorageContextManager;

  beforeAll(() => {
    contextManager = new AsyncLocalStorageContextManager();
    contextManager.enable();
    context.setGlobalContextManager(contextManager);
  });

  afterAll(() => {
    contextManager.disable();
    context.disable();
  });

  it('keeps the shipped default sample rate close to the disabled baseline and clearly cheaper than always-on tracing', async () => {
    const disabledMs = await timeIterations(undefined, ITERATIONS);

    const defaultRate = resolveOtelConfig({}).sampleRate;
    const defaultExporter = new InMemorySpanExporter();
    const defaultProvider = new BasicTracerProvider({
      sampler: new ParentBasedSampler({
        root: new TraceIdRatioBasedSampler(defaultRate),
      }),
      spanProcessors: [new SimpleSpanProcessor(defaultExporter)],
    });
    const defaultMs = await timeIterations(
      defaultProvider.getTracer('benchmark'),
      ITERATIONS,
    );
    // Read the recorded span count *before* shutdown — InMemorySpanExporter
    // clears its buffer as part of shutting down.
    const defaultSpanCount = defaultExporter.getFinishedSpans().length;
    await defaultProvider.shutdown();

    const fullExporter = new InMemorySpanExporter();
    const fullProvider = new BasicTracerProvider({
      sampler: new AlwaysOnSampler(),
      spanProcessors: [new SimpleSpanProcessor(fullExporter)],
    });
    const fullMs = await timeIterations(fullProvider.getTracer('benchmark'), ITERATIONS);
    const fullSpanCount = fullExporter.getFinishedSpans().length;
    await fullProvider.shutdown();

    const disabledPerOpMs = disabledMs / ITERATIONS;
    const defaultPerOpMs = defaultMs / ITERATIONS;
    const fullPerOpMs = fullMs / ITERATIONS;

    // eslint-disable-next-line no-console
    console.info(
      `[tracing benchmark] disabled=${disabledPerOpMs.toFixed(4)}ms/op ` +
        `default(rate=${defaultRate})=${defaultPerOpMs.toFixed(4)}ms/op ` +
        `always-on=${fullPerOpMs.toFixed(4)}ms/op ` +
        `defaultSpans=${defaultSpanCount} fullSpans=${fullSpanCount}`,
    );

    // Absolute overhead per simulated request stays small at the default rate.
    expect(defaultPerOpMs - disabledPerOpMs).toBeLessThan(1);

    // The default rate is measurably cheaper than recording every trace —
    // this is the mechanism that keeps overhead acceptable under load.
    expect(defaultMs).toBeLessThan(fullMs);

    // ~10% of traces are exported at the shipped default vs. 100% when
    // always-on; assert well under half as a low-flake statistical check.
    expect(defaultSpanCount).toBeLessThan(fullSpanCount * 0.5);
  }, 15000);
});
