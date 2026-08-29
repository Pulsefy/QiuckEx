import { context, trace } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from '@opentelemetry/sdk-trace-base';

/**
 * Registers a real (in-memory) tracer provider + AsyncLocalStorage-backed
 * context manager as the OpenTelemetry globals, for tests that exercise
 * span creation and context/baggage propagation.
 *
 * Production wiring (tracing.ts) never runs in tests — NODE_ENV=test keeps
 * `OTEL_ENABLED` off (see otel.config.ts) so the real SDK never starts and
 * the default no-op API is a no-op context manager that does not actually
 * propagate anything. This harness stands in for that real registration.
 */
export interface OtelTestHarness {
  exporter: InMemorySpanExporter;
  getFinishedSpans: () => ReadableSpan[];
  reset: () => void;
  teardown: () => Promise<void>;
}

export function setupOtelTestHarness(): OtelTestHarness {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  const contextManager = new AsyncLocalStorageContextManager();
  contextManager.enable();

  trace.setGlobalTracerProvider(provider);
  context.setGlobalContextManager(contextManager);

  return {
    exporter,
    getFinishedSpans: () => exporter.getFinishedSpans(),
    reset: () => exporter.reset(),
    teardown: async () => {
      contextManager.disable();
      trace.disable();
      context.disable();
      await provider.shutdown();
    },
  };
}
