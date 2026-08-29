import { resolveOtelConfig } from './otel.config';

describe('resolveOtelConfig', () => {
  it('defaults to disabled under NODE_ENV=test so the SDK never starts during Jest runs', () => {
    const config = resolveOtelConfig({ NODE_ENV: 'test' });
    expect(config.enabled).toBe(false);
  });

  it('defaults to enabled outside of NODE_ENV=test', () => {
    expect(resolveOtelConfig({ NODE_ENV: 'development' }).enabled).toBe(true);
    expect(resolveOtelConfig({ NODE_ENV: 'production' }).enabled).toBe(true);
    expect(resolveOtelConfig({}).enabled).toBe(true);
  });

  it('lets OTEL_ENABLED override the NODE_ENV-based default in either direction', () => {
    expect(
      resolveOtelConfig({ NODE_ENV: 'test', OTEL_ENABLED: 'true' }).enabled,
    ).toBe(true);
    expect(
      resolveOtelConfig({ NODE_ENV: 'production', OTEL_ENABLED: 'false' })
        .enabled,
    ).toBe(false);
  });

  it('defaults the sample rate to 0.1 to keep overhead low under load', () => {
    expect(resolveOtelConfig({}).sampleRate).toBe(0.1);
  });

  it('parses and clamps an explicit sample rate to [0, 1]', () => {
    expect(resolveOtelConfig({ OTEL_TRACE_SAMPLE_RATE: '0.5' }).sampleRate).toBe(0.5);
    expect(resolveOtelConfig({ OTEL_TRACE_SAMPLE_RATE: '3' }).sampleRate).toBe(1);
    expect(resolveOtelConfig({ OTEL_TRACE_SAMPLE_RATE: '-2' }).sampleRate).toBe(0);
    expect(resolveOtelConfig({ OTEL_TRACE_SAMPLE_RATE: 'nope' }).sampleRate).toBe(0.1);
  });

  it('defaults the exporter endpoint to a local collector', () => {
    expect(resolveOtelConfig({}).exporterEndpoint).toBe(
      'http://localhost:4318/v1/traces',
    );
  });

  it('appends /v1/traces to a configured base OTLP endpoint', () => {
    expect(
      resolveOtelConfig({
        OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector.internal:4318',
      }).exporterEndpoint,
    ).toBe('http://collector.internal:4318/v1/traces');

    expect(
      resolveOtelConfig({
        OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector.internal:4318/',
      }).exporterEndpoint,
    ).toBe('http://collector.internal:4318/v1/traces');
  });

  it('prefers a signal-specific traces endpoint over the base endpoint, used verbatim', () => {
    expect(
      resolveOtelConfig({
        OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector.internal:4318',
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: 'http://other-collector:4318/v1/traces',
      }).exporterEndpoint,
    ).toBe('http://other-collector:4318/v1/traces');
  });

  it('defaults the service name and falls back service version to APP_VERSION', () => {
    const config = resolveOtelConfig({ APP_VERSION: '1.2.3' });
    expect(config.serviceName).toBe('quickex-backend');
    expect(config.serviceVersion).toBe('1.2.3');
  });

  it('honors explicit OTEL_SERVICE_NAME and OTEL_SERVICE_VERSION overrides', () => {
    const config = resolveOtelConfig({
      OTEL_SERVICE_NAME: 'custom-service',
      OTEL_SERVICE_VERSION: '9.9.9',
      APP_VERSION: '1.2.3',
    });
    expect(config.serviceName).toBe('custom-service');
    expect(config.serviceVersion).toBe('9.9.9');
  });

  it('falls the environment attribute back through OTEL_ENVIRONMENT, SENTRY_ENVIRONMENT, then NODE_ENV', () => {
    expect(resolveOtelConfig({ NODE_ENV: 'staging' }).environment).toBe('staging');
    expect(
      resolveOtelConfig({ NODE_ENV: 'staging', SENTRY_ENVIRONMENT: 'prod-eu' })
        .environment,
    ).toBe('prod-eu');
    expect(
      resolveOtelConfig({
        NODE_ENV: 'staging',
        SENTRY_ENVIRONMENT: 'prod-eu',
        OTEL_ENVIRONMENT: 'canary',
      }).environment,
    ).toBe('canary');
  });

  it('defaults debug logging to off', () => {
    expect(resolveOtelConfig({}).debug).toBe(false);
    expect(resolveOtelConfig({ OTEL_DEBUG: 'true' }).debug).toBe(true);
  });
});
