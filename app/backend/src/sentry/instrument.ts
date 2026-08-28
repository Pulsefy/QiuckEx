/**
 * Sentry instrumentation file.
 * This file MUST be imported before any other modules in main.ts
 * to ensure Sentry can properly hook into Node.js internals.
 *
 * Performance tracing is enabled for transaction paths (compose, simulate,
 * submit) and spans are added for Horizon, Soroban RPC, and cache calls.
 *
 * @see https://docs.sentry.io/platforms/javascript/guides/nestjs/
 */
import * as Sentry from '@sentry/nestjs';
import { nodeProfilingIntegration } from '@sentry/profiling-node';

const SENTRY_DSN = process.env.SENTRY_DSN;
const SENTRY_ENVIRONMENT =
  process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || 'development';
/**
 * Release tag sourced from SENTRY_RELEASE env var, which CI/CD should set
 * to e.g. `quickex-backend@<git-sha>` at build time.
 */
const SENTRY_RELEASE = process.env.SENTRY_RELEASE || 'quickex-backend@0.1.0';
/**
 * Performance monitoring: capture 10% of transactions in production.
 * Override via SENTRY_TRACES_SAMPLE_RATE env var (0.0–1.0).
 */
const SENTRY_TRACES_SAMPLE_RATE = parseFloat(
  process.env.SENTRY_TRACES_SAMPLE_RATE || '0.1',
);
const SENTRY_PROFILES_SAMPLE_RATE = parseFloat(
  process.env.SENTRY_PROFILES_SAMPLE_RATE || '1.0',
);

/** Stellar public key regex: G + 55 base32 chars (56 chars total). */
const STELLAR_PUBLIC_KEY_RE = /\bG[A-Z2-7]{55}\b/g;

/** Replace Stellar public keys with a short redacted token. */
function scrubPublicKeys(value: unknown): unknown {
  if (typeof value === 'string') {
    return value.replace(STELLAR_PUBLIC_KEY_RE, '[STELLAR_PUBLIC_KEY]');
  }
  if (Array.isArray(value)) {
    return value.map(scrubPublicKeys);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [
        k,
        scrubPublicKeys(v),
      ]),
    );
  }
  return value;
}

if (SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: SENTRY_ENVIRONMENT,
    release: SENTRY_RELEASE,

    integrations: [nodeProfilingIntegration()],

    /**
     * Performance monitoring — 10% sample rate.
     * Transactions are created automatically for HTTP requests by
     * @sentry/nestjs via the SentryGlobalFilter integration.
     * Additional spans for Horizon, Soroban RPC and cache operations are
     * added manually via SentryTracingService.
     */
    tracesSampleRate: SENTRY_TRACES_SAMPLE_RATE,

    // Profiling: capture performance profiles for sampled transactions
    profilesSampleRate: SENTRY_PROFILES_SAMPLE_RATE,

    // ── PII scrubbing ────────────────────────────────────────────────────
    beforeSend(event) {
      // Strip sensitive headers
      if (event.request?.headers) {
        delete event.request.headers['authorization'];
        delete event.request.headers['x-api-key'];
        delete event.request.headers['cookie'];
      }

      // Strip sensitive fields and Stellar public keys from request body
      if (event.request?.data) {
        const raw =
          typeof event.request.data === 'string'
            ? tryParseJson(event.request.data)
            : event.request.data;

        if (raw && typeof raw === 'object') {
          // Redact well-known secret fields
          const scrubbed = { ...(raw as Record<string, unknown>) };
          const secretFields = [
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
          for (const field of secretFields) {
            if (field in scrubbed) {
              scrubbed[field] = '[REDACTED]';
            }
          }
          // Scrub any Stellar public keys that slipped through
          event.request.data = scrubPublicKeys(scrubbed);
        }
      }

      // Scrub public keys from extra context and message strings
      if (event.extra) {
        event.extra = scrubPublicKeys(event.extra) as Record<string, unknown>;
      }
      if (event.message) {
        event.message = scrubPublicKeys(event.message) as string;
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
      // Scrub Stellar public keys from breadcrumb data
      if (breadcrumb.data) {
        breadcrumb.data = scrubPublicKeys(breadcrumb.data) as Record<string, unknown>;
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
