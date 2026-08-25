/**
 * Unit tests for label cardinality protection (BE-115).
 *
 * Verifies:
 * 1. `sanitizeLabel` passes through valid allowlisted values unchanged.
 * 2. `sanitizeLabel` returns "other" for any value NOT in the allowlist.
 * 3. MetricsService applies sanitization before calling `.labels()` for every
 *    label dimension that can receive unbounded/user-controlled input.
 * 4. MetricsGuard is fail-closed when METRICS_ENDPOINT_TOKEN is not set.
 *
 * CARDINALITY CONTRACT: any test in this file that calls a MetricsService
 * method with an out-of-allowlist value MUST assert that the underlying
 * prom-client `.labels()` call received "other", not the raw value.
 * If this assertion is removed or weakened the pipeline should fail.
 */

import { Test } from '@nestjs/testing';
import {
  sanitizeLabel,
  LABEL_OVERFLOW,
  ALLOWED_EVENT_TYPES,
  ALLOWED_WEBHOOK_STATUSES,
  ALLOWED_RPC_FAILOVER_REASONS,
  ALLOWED_EVENT_NAMES,
  ALLOWED_ABUSE_TAGS,
  ALLOWED_ABUSE_ACTION_TYPES,
  ALLOWED_SERVICES,
} from './label-allowlist';
import { MetricsService } from './metrics.service';
import { MetricsGuard } from './metrics.guard';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

// ---------------------------------------------------------------------------
// Minimal prom-client stubs (avoid real registry in unit tests)
// ---------------------------------------------------------------------------

const mockLabels = jest.fn().mockReturnThis();
const mockInc = jest.fn();
const mockObserve = jest.fn();
const mockSet = jest.fn();

jest.mock('prom-client', () => ({
  Registry: jest.fn().mockImplementation(() => ({
    registerMetric: jest.fn(),
    metrics: jest.fn().mockResolvedValue(''),
    contentType: 'text/plain',
  })),
  collectDefaultMetrics: jest.fn(),
  Histogram: jest.fn().mockImplementation(() => ({
    labels: mockLabels,
    observe: mockObserve,
  })),
  Counter: jest.fn().mockImplementation(() => ({
    labels: mockLabels,
    inc: mockInc,
  })),
  Gauge: jest.fn().mockImplementation(() => ({
    labels: mockLabels,
    set: mockSet,
    inc: jest.fn(),
    dec: jest.fn(),
  })),
}));

// ---------------------------------------------------------------------------
// sanitizeLabel – pure-function tests
// ---------------------------------------------------------------------------

describe('sanitizeLabel', () => {
  it('passes through a value that is in the allowlist', () => {
    expect(sanitizeLabel('payment.received', ALLOWED_EVENT_TYPES)).toBe('payment.received');
    expect(sanitizeLabel('success', ALLOWED_WEBHOOK_STATUSES)).toBe('success');
    expect(sanitizeLabel('supabase', ALLOWED_SERVICES)).toBe('supabase');
  });

  it('returns LABEL_OVERFLOW ("other") for any value NOT in the allowlist', () => {
    // Free-form user data
    expect(sanitizeLabel('user-1234-secret', ALLOWED_EVENT_TYPES)).toBe(LABEL_OVERFLOW);
    expect(sanitizeLabel('GBADACTOR...', ALLOWED_SERVICES)).toBe(LABEL_OVERFLOW);
    expect(sanitizeLabel('sqli\' OR 1=1--', ALLOWED_ABUSE_TAGS)).toBe(LABEL_OVERFLOW);
  });

  it('returns LABEL_OVERFLOW for an empty string when the allowlist does not include it', () => {
    expect(sanitizeLabel('', ALLOWED_EVENT_TYPES)).toBe(LABEL_OVERFLOW);
  });

  it('returns the value unchanged when allowlist explicitly contains an empty string', () => {
    expect(sanitizeLabel('', [''] as const)).toBe('');
  });

  it('is case-sensitive – wrong case is treated as unknown', () => {
    expect(sanitizeLabel('Payment.Received', ALLOWED_EVENT_TYPES)).toBe(LABEL_OVERFLOW);
    expect(sanitizeLabel('SUCCESS', ALLOWED_WEBHOOK_STATUSES)).toBe(LABEL_OVERFLOW);
  });

  it('collapses all unknown values to the same "other" sentinel', () => {
    const unknowns = ['foo', 'bar', 'baz', 'PAYMENT_ID_12345', 'contract:GABCD...'];
    for (const u of unknowns) {
      expect(sanitizeLabel(u, ALLOWED_EVENT_TYPES)).toBe('other');
    }
  });

  // ------------------------------------------------------------------
  // CARDINALITY CONTRACT TEST
  // If you remove this test or weaken its assertion the CI pipeline MUST fail.
  // ------------------------------------------------------------------
  it('[CARDINALITY CONTRACT] rejects any value not in the supplied allowlist (unbounded label guard)', () => {
    const unboundedValues = [
      'user_id:GABC123',
      'tx_hash:abc123def456',
      'contract:CDEF789',
      'payment_link_id:plnk_xyz',
      'username:alice@example.com',
    ];

    for (const value of unboundedValues) {
      expect(sanitizeLabel(value, ALLOWED_EVENT_TYPES)).toBe(LABEL_OVERFLOW);
    }
  });
});

// ---------------------------------------------------------------------------
// MetricsService – cardinality guard integration
// ---------------------------------------------------------------------------

describe('MetricsService – cardinality protection', () => {
  let service: MetricsService;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockLabels.mockReturnThis();

    const module = await Test.createTestingModule({
      providers: [MetricsService],
    }).compile();

    service = module.get<MetricsService>(MetricsService);
    service.onModuleInit();
  });

  describe('recordWebhookRetry', () => {
    it('passes allowlisted event_type through unchanged', () => {
      service.recordWebhookRetry('payment.received', 'success');
      expect(mockLabels).toHaveBeenCalledWith('payment.received', 'success');
    });

    it('[CARDINALITY] collapses unknown event_type to "other"', () => {
      service.recordWebhookRetry('user-supplied-event-type', 'success');
      expect(mockLabels).toHaveBeenCalledWith('other', 'success');
    });

    it('[CARDINALITY] collapses unknown status to "other"', () => {
      service.recordWebhookRetry('payment.received', 'UNKNOWN_STATUS_12345');
      expect(mockLabels).toHaveBeenCalledWith('payment.received', 'other');
    });
  });

  describe('recordWebhookDeliveryDuration', () => {
    it('[CARDINALITY] collapses unknown event_type to "other"', () => {
      service.recordWebhookDeliveryDuration('tx-id-12345', 'success', 0.3);
      expect(mockLabels).toHaveBeenCalledWith('other', 'success');
    });

    it('[CARDINALITY] collapses unknown status to "other"', () => {
      service.recordWebhookDeliveryDuration('payment.received', 'http-200-ok-????', 0.3);
      expect(mockLabels).toHaveBeenCalledWith('payment.received', 'other');
    });
  });

  describe('recordExternalCall', () => {
    it('passes an allowlisted service name through unchanged', () => {
      service.recordExternalCall('supabase', 'query', 0.05);
      expect(mockLabels).toHaveBeenCalledWith('supabase', 'query');
    });

    it('[CARDINALITY] collapses an unknown service name to "other"', () => {
      service.recordExternalCall('some-internal-microservice-v3', 'fetch', 0.1);
      expect(mockLabels).toHaveBeenCalledWith('other', 'fetch');
    });
  });

  describe('recordError', () => {
    it('[CARDINALITY] collapses an unknown service name to "other"', () => {
      service.recordError('user_id:GABCDEF', 'NotFound');
      expect(mockLabels).toHaveBeenCalledWith('other', 'NotFound');
    });
  });

  describe('recordSorobanRpcFailover', () => {
    it('[CARDINALITY] collapses an unknown reason to "other"', () => {
      service.recordSorobanRpcFailover(
        'https://rpc-1.example.com',
        'https://rpc-2.example.com',
        'arbitrary-reason-from-user-input',
      );
      expect(mockLabels).toHaveBeenCalledWith('other', 'other', 'other');
    });

    it('passes an allowlisted reason through unchanged when endpoints are also sanitized', () => {
      service.recordSorobanRpcFailover(
        'https://rpc-1.example.com',
        'https://rpc-2.example.com',
        'network timeout',
      );
      // Endpoints map to "other" (not in any allowlist), reason is known
      expect(mockLabels).toHaveBeenCalledWith('other', 'other', 'network timeout');
    });
  });

  describe('recordUnknownSchemaVersion', () => {
    it('[CARDINALITY] collapses an unknown event name to "other"', () => {
      service.recordUnknownSchemaVersion('UnknownEventFromFuture', 99);
      expect(mockLabels).toHaveBeenCalledWith('other', '99');
    });

    it('passes an allowlisted event name through unchanged', () => {
      service.recordUnknownSchemaVersion('EscrowDeposited', 2);
      expect(mockLabels).toHaveBeenCalledWith('EscrowDeposited', '2');
    });
  });

  describe('recordAbuseSignal – top_tag cardinality', () => {
    it('[CARDINALITY] collapses a free-form top_tag to "other" for high-score signals', () => {
      service.recordAbuseSignal('payment', 'blocked', 85, ['arbitrary-user-tag-12345']);
      // The scoreRange label is "80-100", topTag should be "other"
      expect(mockLabels).toHaveBeenCalledWith('80-100', 'other');
    });

    it('passes an allowlisted top_tag through unchanged', () => {
      service.recordAbuseSignal('payment', 'blocked', 55, ['spam']);
      expect(mockLabels).toHaveBeenCalledWith('50-79', 'spam');
    });

    it('[CARDINALITY] collapses an unknown action_type to "other"', () => {
      service.recordAbuseSignal('free_form_action_type_xyz', 'blocked', 10, []);
      expect(mockLabels).toHaveBeenCalledWith('other', 'blocked');
    });
  });

  describe('recordOutboxDispatch', () => {
    it('[CARDINALITY] collapses an unknown event_type to "other"', () => {
      service.recordOutboxDispatch('internal-event-name-not-in-allowlist', 'success');
      expect(mockLabels).toHaveBeenCalledWith('other', 'success');
    });

    it('passes an allowlisted event_type through unchanged', () => {
      service.recordOutboxDispatch('export.completed', 'success');
      expect(mockLabels).toHaveBeenCalledWith('export.completed', 'success');
    });
  });
});

// ---------------------------------------------------------------------------
// MetricsGuard – access control hardening
// ---------------------------------------------------------------------------

describe('MetricsGuard – fail-closed access control', () => {
  function makeContext(token?: string): ExecutionContext {
    return {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: token !== undefined ? { 'x-metrics-token': token } : {},
        }),
      }),
    } as unknown as ExecutionContext;
  }

  it('allows access when the correct token is supplied', () => {
    const guard = new MetricsGuard({
      get: () => 'super-secret-token',
    } as unknown as ConfigService);

    expect(guard.canActivate(makeContext('super-secret-token'))).toBe(true);
  });

  it('throws UnauthorizedException for a wrong token', () => {
    const guard = new MetricsGuard({
      get: () => 'super-secret-token',
    } as unknown as ConfigService);

    expect(() => guard.canActivate(makeContext('wrong-token'))).toThrow(
      UnauthorizedException,
    );
  });

  it('[SECURITY] throws UnauthorizedException when METRICS_ENDPOINT_TOKEN env var is not set (fail-closed)', () => {
    const guard = new MetricsGuard({
      get: () => undefined,
    } as unknown as ConfigService);

    // Even sending the correct value should be rejected when no token is configured
    expect(() => guard.canActivate(makeContext(undefined))).toThrow(UnauthorizedException);
    expect(() => guard.canActivate(makeContext(''))).toThrow(UnauthorizedException);
    expect(() => guard.canActivate(makeContext('any-token'))).toThrow(UnauthorizedException);
  });

  it('[SECURITY] throws UnauthorizedException when METRICS_ENDPOINT_TOKEN is an empty string (fail-closed)', () => {
    const guard = new MetricsGuard({
      get: () => '',
    } as unknown as ConfigService);

    expect(() => guard.canActivate(makeContext(''))).toThrow(UnauthorizedException);
  });

  it('throws UnauthorizedException when X-Metrics-Token header is missing', () => {
    const guard = new MetricsGuard({
      get: () => 'super-secret-token',
    } as unknown as ConfigService);

    expect(() => guard.canActivate(makeContext(undefined))).toThrow(UnauthorizedException);
  });
});
