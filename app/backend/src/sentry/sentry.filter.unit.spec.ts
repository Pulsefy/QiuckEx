import { SentryExceptionFilter } from './sentry.filter';
import { SentryService } from './sentry.service';
import { AppConfigService } from '../config';
import { HttpException, HttpStatus } from '@nestjs/common';

describe('SentryExceptionFilter', () => {
  let filter: SentryExceptionFilter;
  let mockSentryService: jest.Mocked<SentryService>;
  let mockConfigService: jest.Mocked<AppConfigService>;
  let mockHost: {
    switchToHttp: jest.Mock;
  };
  let mockRequest: Record<string, unknown>;

  beforeEach(() => {
    mockSentryService = {
      captureException: jest.fn(),
      captureMessage: jest.fn(),
      isEnabled: true,
    } as unknown as jest.Mocked<SentryService>;

    mockConfigService = {
      isProduction: false,
    } as unknown as jest.Mocked<AppConfigService>;

    mockRequest = {
      method: 'POST',
      url: '/api/payments',
      headers: {
        'user-agent': 'test-agent',
        'content-type': 'application/json',
        authorization: 'Bearer secret-token',
      },
      ip: '127.0.0.1',
      query: {},
      body: { amount: '100', token: 'secret-value' },
      correlationId: 'test-correlation-id',
    };

    mockHost = {
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue(mockRequest),
        getResponse: jest.fn().mockReturnValue({}),
      }),
    };

    filter = new SentryExceptionFilter(mockSentryService, mockConfigService);
  });

  it('should report 500 errors to Sentry', () => {
    const error = new Error('Database connection failed');

    expect(() => {
      filter.catch(error, mockHost as never);
    }).toThrow(error);

    expect(mockSentryService.captureException).toHaveBeenCalledWith(
      error,
      expect.objectContaining({
        method: 'POST',
        url: '/api/payments',
        correlationId: 'test-correlation-id',
        httpStatus: 500,
      }),
    );
  });

  it('should NOT report 4xx errors to Sentry', () => {
    const error = new HttpException('Not found', HttpStatus.NOT_FOUND);

    expect(() => {
      filter.catch(error, mockHost as never);
    }).toThrow(error);

    expect(mockSentryService.captureException).not.toHaveBeenCalled();
  });

  it('should report HttpException with 5xx status', () => {
    const error = new HttpException(
      'Service unavailable',
      HttpStatus.SERVICE_UNAVAILABLE,
    );

    expect(() => {
      filter.catch(error, mockHost as never);
    }).toThrow(error);

    expect(mockSentryService.captureException).toHaveBeenCalledWith(
      error,
      expect.objectContaining({ httpStatus: 503 }),
    );
  });

  it('should sanitise sensitive fields in request body', () => {
    const error = new Error('Crash');

    expect(() => {
      filter.catch(error, mockHost as never);
    }).toThrow(error);

    const capturedExtras =
      mockSentryService.captureException.mock.calls[0][1] as Record<
        string,
        unknown
      >;
    const body = capturedExtras.body as Record<string, unknown>;
    expect(body.amount).toBe('100');
    expect(body.token).toBe('[REDACTED]');
  });

  it('should exclude sensitive headers', () => {
    const error = new Error('Crash');

    expect(() => {
      filter.catch(error, mockHost as never);
    }).toThrow(error);

    const capturedExtras =
      mockSentryService.captureException.mock.calls[0][1] as Record<
        string,
        unknown
      >;
    const headers = capturedExtras.headers as Record<string, unknown>;
    expect(headers['authorization']).toBeUndefined();
    expect(headers['content-type']).toBe('application/json');
  });
});
