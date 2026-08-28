/**
 * Unit tests for StellarExceptionMapper (issue #24).
 *
 * Covers:
 * - ConnectionError → 502
 * - NotFoundError → 404
 * - RateLimitError → 429 with Retry-After
 * - ContractError → 400 with code/details
 * - Timeout → 504
 * - Unmapped → 500 without stack trace in response
 * - traceId embedded in every mapped error
 */

import { HttpStatus } from '@nestjs/common';
import {
  mapStellarException,
  throwMappedStellarException,
  StellarErrorCode,
} from './stellar-exception.mapper';

// ── helpers ───────────────────────────────────────────────────────────────────

function makeError(msg: string, extras: Record<string, unknown> = {}): Error & Record<string, unknown> {
  const err = new Error(msg) as Error & Record<string, unknown>;
  Object.assign(err, extras);
  return err;
}

function makeHorizonError(msg: string, status: number) {
  return makeError(msg, { response: { status } });
}

// ── mapStellarException ───────────────────────────────────────────────────────

describe('mapStellarException', () => {
  describe('ConnectionError → 502', () => {
    it.each([
      'NetworkError: failed to fetch',
      'FetchError: fetch failed',
      'ECONNREFUSED 127.0.0.1:443',
      'ECONNRESET',
      'ENOTFOUND horizon.stellar.org',
      'Connection refused',
    ])('maps "%s" to BAD_GATEWAY', (msg) => {
      const result = mapStellarException(makeError(msg));
      expect(result.httpStatus).toBe(HttpStatus.BAD_GATEWAY);
      expect(result.code).toBe(StellarErrorCode.CONNECTION_ERROR);
    });
  });

  describe('NotFoundError → 404', () => {
    it('maps HTTP 404 status to NOT_FOUND', () => {
      const result = mapStellarException(makeHorizonError('Resource not found', 404));
      expect(result.httpStatus).toBe(HttpStatus.NOT_FOUND);
      expect(result.code).toBe(StellarErrorCode.NOT_FOUND);
    });

    it('maps "account not found" message to NOT_FOUND', () => {
      const result = mapStellarException(makeError('account not found on the network'));
      expect(result.httpStatus).toBe(HttpStatus.NOT_FOUND);
      expect(result.code).toBe(StellarErrorCode.NOT_FOUND);
    });
  });

  describe('RateLimitError → 429 with Retry-After', () => {
    it('maps HTTP 429 status to TOO_MANY_REQUESTS', () => {
      const result = mapStellarException(
        makeHorizonError('Too Many Requests', 429),
      );
      expect(result.httpStatus).toBe(HttpStatus.TOO_MANY_REQUESTS);
      expect(result.code).toBe(StellarErrorCode.RATE_LIMITED);
    });

    it('includes retryAfter from Retry-After header when present', () => {
      const err = makeError('rate limit exceeded');
      err['response'] = { status: 429, headers: { 'retry-after': '30' } };
      const result = mapStellarException(err);
      expect(result.retryAfter).toBe(30);
    });

    it('defaults retryAfter to 60 when header is absent', () => {
      const result = mapStellarException(makeHorizonError('Too Many Requests', 429));
      expect(result.retryAfter).toBe(60);
    });
  });

  describe('ContractError → 400 with code/details', () => {
    it('maps HostError string to BAD_REQUEST', () => {
      const result = mapStellarException(
        makeError('HostError: Error(Auth, NotAuthorized)'),
      );
      expect(result.httpStatus).toBe(HttpStatus.BAD_REQUEST);
      expect(result.code).toBe(StellarErrorCode.CONTRACT_ERROR);
    });

    it('extracts errorType and errorCode from HostError string', () => {
      const result = mapStellarException(
        makeError('simulation failed: Error(Storage, MissingValue)'),
      );
      expect(result.details).toEqual({ errorType: 'Storage', errorCode: 'MissingValue' });
    });

    it('handles Soroban simulation failure message', () => {
      const result = mapStellarException(makeError('simulation failed with contract error'));
      expect(result.httpStatus).toBe(HttpStatus.BAD_REQUEST);
    });
  });

  describe('Timeout → 504', () => {
    it.each([
      'Request timeout after 10000ms',
      'ETIMEDOUT',
      'Operation timed out',
    ])('maps "%s" to GATEWAY_TIMEOUT', (msg) => {
      const result = mapStellarException(makeError(msg));
      expect(result.httpStatus).toBe(HttpStatus.GATEWAY_TIMEOUT);
      expect(result.code).toBe(StellarErrorCode.TIMEOUT);
    });
  });

  describe('Unmapped → 500', () => {
    it('maps an unrecognised error to INTERNAL_SERVER_ERROR', () => {
      const result = mapStellarException(new Error('some random error'));
      expect(result.httpStatus).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(result.code).toBe(StellarErrorCode.INTERNAL);
    });

    it('does not include stack trace in the mapped result', () => {
      const result = mapStellarException(new Error('unknown'));
      expect(result).not.toHaveProperty('stack');
    });
  });
});

// ── throwMappedStellarException ───────────────────────────────────────────────

describe('throwMappedStellarException', () => {
  it('throws NotFoundException (404) for not-found errors', () => {
    expect(() =>
      throwMappedStellarException(makeHorizonError('Not Found', 404), 'trace-1'),
    ).toThrow(expect.objectContaining({ status: 404 }));
  });

  it('throws TooManyRequestsException (429) for rate limit errors', () => {
    expect(() =>
      throwMappedStellarException(makeHorizonError('Rate limited', 429), 'trace-2'),
    ).toThrow(expect.objectContaining({ status: 429 }));
  });

  it('throws BadRequestException (400) for contract errors', () => {
    expect(() =>
      throwMappedStellarException(makeError('HostError: Error(Auth, NotAuthorized)'), 'trace-3'),
    ).toThrow(expect.objectContaining({ status: 400 }));
  });

  it('throws BadGatewayException (502) for connection errors', () => {
    expect(() =>
      throwMappedStellarException(makeError('NetworkError: failed to fetch'), 'trace-4'),
    ).toThrow(expect.objectContaining({ status: 502 }));
  });

  it('throws GatewayTimeoutException (504) for timeouts', () => {
    expect(() =>
      throwMappedStellarException(makeError('Request timeout after 10000ms'), 'trace-5'),
    ).toThrow(expect.objectContaining({ status: 504 }));
  });

  it('throws HttpException (500) for unmapped errors', () => {
    expect(() =>
      throwMappedStellarException(new Error('unknown random error'), 'trace-6'),
    ).toThrow(expect.objectContaining({ status: 500 }));
  });

  it('embeds traceId in the response body', () => {
    let thrownError: unknown;
    try {
      throwMappedStellarException(makeHorizonError('Not Found', 404), 'my-trace-id');
    } catch (err) {
      thrownError = err;
    }
    const response = (thrownError as { getResponse(): unknown }).getResponse();
    expect(response).toMatchObject({ traceId: 'my-trace-id' });
  });

  it('works without a traceId', () => {
    expect(() =>
      throwMappedStellarException(makeHorizonError('Not Found', 404)),
    ).toThrow();
  });

  it('includes contract details for HostError exceptions', () => {
    let thrownError: unknown;
    try {
      throwMappedStellarException(makeError('simulation failed: Error(Storage, MissingValue)'));
    } catch (err) {
      thrownError = err;
    }
    const response = (thrownError as { getResponse(): unknown }).getResponse();
    expect(response).toMatchObject({
      details: { errorType: 'Storage', errorCode: 'MissingValue' },
    });
  });
});
