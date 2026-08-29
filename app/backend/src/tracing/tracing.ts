/**
 * OpenTelemetry bootstrap. MUST be the first thing `main.ts` imports so the
 * http/express/undici instrumentation can patch those modules before
 * anything else requires them — same constraint as `sentry/instrument.ts`.
 *
 * Starts a trace pipeline covering inbound HTTP requests (Nest/Express),
 * outbound Soroban RPC + Horizon calls (axios and native fetch both ride on
 * top of core `http`/undici), and Supabase/PostgREST DB calls (native
 * fetch), all joined by W3C trace context propagation across the same
 * AsyncLocalStorage-backed context Node uses for async continuations.
 */
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { NestInstrumentation } from '@opentelemetry/instrumentation-nestjs-core';
import { UndiciInstrumentation } from '@opentelemetry/instrumentation-undici';
import { defaultResource, resourceFromAttributes } from '@opentelemetry/resources';
import { NodeSDK } from '@opentelemetry/sdk-node';
import {
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
} from '@opentelemetry/sdk-trace-base';
import {
  ATTR_DEPLOYMENT_ENVIRONMENT_NAME,
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from '@opentelemetry/semantic-conventions';

import { resolveOtelConfig } from './otel.config';

const config = resolveOtelConfig();

/** Noisy, high-volume, low-value endpoints hit by Prometheus/uptime checks. */
const UNTRACED_PATH_PREFIXES = ['/metrics', '/health'];

let sdk: NodeSDK | undefined;

if (config.enabled) {
  if (config.debug) {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.INFO);
  }

  sdk = new NodeSDK({
    resource: defaultResource().merge(
      resourceFromAttributes({
        [ATTR_SERVICE_NAME]: config.serviceName,
        [ATTR_SERVICE_VERSION]: config.serviceVersion,
        [ATTR_DEPLOYMENT_ENVIRONMENT_NAME]: config.environment,
      }),
    ),
    traceExporter: new OTLPTraceExporter({ url: config.exporterEndpoint }),
    sampler: new ParentBasedSampler({
      root: new TraceIdRatioBasedSampler(config.sampleRate),
    }),
    instrumentations: [
      new HttpInstrumentation({
        ignoreIncomingRequestHook: (req) => {
          const url = req.url ?? '';
          return UNTRACED_PATH_PREFIXES.some((prefix) => url.startsWith(prefix));
        },
      }),
      new ExpressInstrumentation(),
      new UndiciInstrumentation(),
      new NestInstrumentation(),
    ],
  });

  try {
    sdk.start();
    // eslint-disable-next-line no-console
    console.log(
      `[OpenTelemetry] Tracing initialized (service=${config.serviceName}, sampleRate=${config.sampleRate}, exporter=${config.exporterEndpoint})`,
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[OpenTelemetry] Failed to initialize tracing SDK', err);
  }

  const shutdown = () => {
    sdk
      ?.shutdown()
      // eslint-disable-next-line no-console
      .catch((err) => console.error('[OpenTelemetry] Error shutting down tracing SDK', err));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
} else {
  // eslint-disable-next-line no-console
  console.log('[OpenTelemetry] Tracing disabled (OTEL_ENABLED=false)');
}

export { sdk };
