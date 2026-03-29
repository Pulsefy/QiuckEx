/**
 * Sentry instrumentation file.
 * This file MUST be imported before any other modules in main.ts
 * to ensure Sentry can properly hook into Node.js internals.
 *
 * @see https://docs.sentry.io/platforms/javascript/guides/nestjs/
 */
import * as Sentry from '@sentry/nestjs';
import { nodeProfilingIntegration } from '@sentry/profiling-node';

const SENTRY_DSN = process.env.SENTRY_DSN;
const SENTRY_ENVIRONMENT =
  process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || 'development';
const SENTRY_RELEASE = process.env.SENTRY_RELEASE || 'quickex-backend@0.1.0';
const SENTRY_TRACES_SAMPLE_RATE = parseFloat(
  process.env.SENTRY_TRACES_SAMPLE_RATE || '1.0',
);
const SENTRY_PROFILES_SAMPLE_RATE = parseFloat(
  process.env.SENTRY_PROFILES_SAMPLE_RATE || '1.0',
);

if (SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: SENTRY_ENVIRONMENT,
    release: SENTRY_RELEASE,

    integrations: [nodeProfilingIntegration()],

    // Performance monitoring: capture a percentage of transactions
    tracesSampleRate: SENTRY_TRACES_SAMPLE_RATE,

    // Profiling: capture performance profiles
    profilesSampleRate: SENTRY_PROFILES_SAMPLE_RATE,

    // Filter out sensitive data before sending to Sentry
    beforeSend(event) {
      // Strip sensitive headers
      if (event.request?.headers) {
        delete event.request.headers['authorization'];
        delete event.request.headers['x-api-key'];
        delete event.request.headers['cookie'];
      }

      // Strip sensitive data from request body
      if (event.request?.data) {
        const data =
          typeof event.request.data === 'string'
            ? tryParseJson(event.request.data)
            : event.request.data;

        if (data && typeof data === 'object') {
          const sanitized = { ...data };
          const sensitiveFields = [
            'password',
            'token',
            'secret',
            'secretKey',
            'apiKey',
            'api_key',
            'stellar_secret_key',
            'private_key',
            'mnemonic',
            'seed',
          ];
          for (const field of sensitiveFields) {
            if (field in sanitized) {
              sanitized[field] = '[REDACTED]';
            }
          }
          event.request.data = sanitized;
        }
      }

      return event;
    },

    // Filter breadcrumbs to avoid leaking sensitive info
    beforeBreadcrumb(breadcrumb) {
      // Remove sensitive query params from URL breadcrumbs
      if (breadcrumb.category === 'http' && breadcrumb.data?.url) {
        try {
          const url = new URL(breadcrumb.data.url);
          const sensitiveParams = ['token', 'key', 'secret', 'password'];
          for (const param of sensitiveParams) {
            if (url.searchParams.has(param)) {
              url.searchParams.set(param, '[REDACTED]');
            }
          }
          breadcrumb.data.url = url.toString();
        } catch {
          // URL parsing failed — leave breadcrumb as-is
        }
      }
      return breadcrumb;
    },

    // Ignore common non-actionable errors
    ignoreErrors: [
      // Network errors from clients disconnecting
      'ECONNRESET',
      'EPIPE',
      'ECONNABORTED',
      // Rate limiting (expected behaviour)
      'ThrottlerException',
    ],
  });
} else {
  // eslint-disable-next-line no-console
  console.warn(
    '[Sentry] SENTRY_DSN not set — error monitoring is disabled. ' +
      'Set SENTRY_DSN in your environment to enable Sentry.',
  );
}

function tryParseJson(str: string): Record<string, unknown> | null {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}
