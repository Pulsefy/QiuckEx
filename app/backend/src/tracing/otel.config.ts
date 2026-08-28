/**
 * Pure config resolution for OpenTelemetry tracing.
 *
 * This is consumed directly from `tracing.ts` (which runs before the Nest
 * DI container exists, so it cannot use `ConfigService`) and mirrored by
 * Joi entries in `env.schema.ts` so the same variables are documented and
 * validated the normal way for the rest of the app.
 */
export interface OtelConfig {
  /** Master on/off switch. Defaults to enabled outside of NODE_ENV=test. */
  enabled: boolean;
  serviceName: string;
  serviceVersion: string;
  environment: string;
  /** Full OTLP/HTTP traces endpoint, e.g. http://localhost:4318/v1/traces */
  exporterEndpoint: string;
  /** Root sampling ratio, 0..1. */
  sampleRate: number;
  debug: boolean;
}

const DEFAULT_SERVICE_NAME = 'quickex-backend';
const DEFAULT_EXPORTER_ENDPOINT = 'http://localhost:4318/v1/traces';
/**
 * Kept low by default so tracing overhead stays negligible under load
 * (see tracing.benchmark.spec.ts) while still sampling enough traces to be
 * useful for diagnosing slow payment flows.
 */
const DEFAULT_SAMPLE_RATE = 0.1;

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  return value.trim().toLowerCase() === 'true';
}

function parseSampleRate(value: string | undefined): number {
  if (value === undefined || value.trim() === '') return DEFAULT_SAMPLE_RATE;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return DEFAULT_SAMPLE_RATE;
  return Math.min(1, Math.max(0, parsed));
}

function resolveExporterEndpoint(env: NodeJS.ProcessEnv): string {
  const tracesEndpoint = env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT?.trim();
  if (tracesEndpoint) return tracesEndpoint;

  const baseEndpoint = env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim();
  if (baseEndpoint) {
    return `${baseEndpoint.replace(/\/+$/, '')}/v1/traces`;
  }

  return DEFAULT_EXPORTER_ENDPOINT;
}

export function resolveOtelConfig(
  env: NodeJS.ProcessEnv = process.env,
): OtelConfig {
  const nodeEnv = env.NODE_ENV || 'development';
  const isTestEnv = nodeEnv === 'test';

  return {
    enabled: parseBoolean(env.OTEL_ENABLED, !isTestEnv),
    serviceName: env.OTEL_SERVICE_NAME?.trim() || DEFAULT_SERVICE_NAME,
    serviceVersion:
      env.OTEL_SERVICE_VERSION?.trim() || env.APP_VERSION?.trim() || '0.0.0',
    environment:
      env.OTEL_ENVIRONMENT?.trim() ||
      env.SENTRY_ENVIRONMENT?.trim() ||
      nodeEnv,
    exporterEndpoint: resolveExporterEndpoint(env),
    sampleRate: parseSampleRate(env.OTEL_TRACE_SAMPLE_RATE),
    debug: parseBoolean(env.OTEL_DEBUG, false),
  };
}
