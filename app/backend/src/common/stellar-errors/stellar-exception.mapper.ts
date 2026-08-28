/**
 * StellarExceptionMapper
 *
 * Maps exceptions thrown by the Stellar SDK (Horizon HTTP errors, network
 * errors, rate-limit responses, Soroban contract errors) to stable NestJS
 * `HttpException` sub-classes with consistent HTTP status codes.
 *
 * Every mapped exception includes a `traceId` (correlation ID) so clients
 * can reference a specific error in support requests.
 *
 * ## Status code mapping
 *
 * | Stellar exception kind          | HTTP status | Error code              |
 * |---------------------------------|-------------|-------------------------|
 * | Connection / network error      | 502         | STELLAR_CONNECTION_ERROR|
 * | Timeout                         | 504         | STELLAR_TIMEOUT         |
 * | 404 / account not found         | 404         | STELLAR_NOT_FOUND       |
 * | 429 / rate limited              | 429         | STELLAR_RATE_LIMITED    |
 * | Soroban contract error          | 400         | CONTRACT_ERROR          |
 * | Other SDK errors                | 500         | STELLAR_ERROR (no stack)|
 *
 * Unmapped exceptions → 500, no stack trace in the response body.
 */

import {
  BadGatewayException,
  BadRequestException,
  GatewayTimeoutException,
  HttpException,
  HttpStatus,
  NotFoundException,
  TooManyRequestsException,
} from '@nestjs/common';

/** Stable error code constants surfaced to API consumers. */
export const StellarErrorCode = {
  CONNECTION_ERROR: 'STELLAR_CONNECTION_ERROR',
  TIMEOUT: 'STELLAR_TIMEOUT',
  NOT_FOUND: 'STELLAR_NOT_FOUND',
  RATE_LIMITED: 'STELLAR_RATE_LIMITED',
  CONTRACT_ERROR: 'CONTRACT_ERROR',
  INTERNAL: 'STELLAR_ERROR',
} as const;

export type StellarErrorCodeValue = (typeof StellarErrorCode)[keyof typeof StellarErrorCode];

export interface MappedStellarError {
  /** Stable error code clients can switch on. */
  code: StellarErrorCodeValue;
  /** HTTP status to respond with. */
  httpStatus: number;
  /** Human-readable message safe to surface in UI. */
  message: string;
  /** Retry-After seconds (only present for RATE_LIMITED). */
  retryAfter?: number;
  /** Additional structured details (only for CONTRACT_ERROR). */
  details?: Record<string, unknown>;
}

// ── Type guards for Stellar SDK error shapes ──────────────────────────────────

/**
 * Horizon network errors surfaced by the SDK look like:
 *   { extras: { result_codes: { ... } }, response: { status: number } }
 */
function isHorizonNetworkError(err: unknown): boolean {
  const msg = getErrorMessage(err).toLowerCase();
  return (
    msg.includes('networkerror') ||
    msg.includes('network error') ||
    msg.includes('econnrefused') ||
    msg.includes('econnreset') ||
    msg.includes('epipe') ||
    msg.includes('enotfound') ||
    msg.includes('failed to fetch') ||
    msg.includes('fetch failed') ||
    msg.includes('connection refused')
  );
}

function isTimeoutError(err: unknown): boolean {
  const msg = getErrorMessage(err).toLowerCase();
  return (
    msg.includes('timeout') ||
    msg.includes('etimedout') ||
    msg.includes('timed out')
  );
}

function isNotFoundError(err: unknown): boolean {
  const msg = getErrorMessage(err).toLowerCase();
  const status = getHttpStatus(err);
  return status === 404 || msg.includes('not found') || msg.includes('account not found');
}

function isRateLimitError(err: unknown): boolean {
  const msg = getErrorMessage(err).toLowerCase();
  const status = getHttpStatus(err);
  return status === 429 || msg.includes('rate limit') || msg.includes('too many requests');
}

function isContractError(err: unknown): boolean {
  const msg = getErrorMessage(err);
  return (
    msg.includes('HostError') ||
    msg.includes('Contract') ||
    msg.includes('soroban') ||
    msg.includes('simulation failed') ||
    /Error\(\w+,\s*\w+\)/.test(msg)
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message ?? '';
  if (err && typeof err === 'object') {
    const e = err as Record<string, unknown>;
    if (typeof e['message'] === 'string') return e['message'];
    if (typeof e['detail'] === 'string') return e['detail'];
  }
  return String(err ?? '');
}

function getHttpStatus(err: unknown): number | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const e = err as Record<string, unknown>;
  if (typeof e['status'] === 'number') return e['status'];
  if (e['response'] && typeof e['response'] === 'object') {
    const r = e['response'] as Record<string, unknown>;
    if (typeof r['status'] === 'number') return r['status'];
  }
  return undefined;
}

function extractRetryAfter(err: unknown): number | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const e = err as Record<string, unknown>;
  const headers =
    (e['response'] as Record<string, unknown> | undefined)?.['headers'] as
      | Record<string, string>
      | undefined;
  if (!headers) return undefined;
  const raw = headers['retry-after'] ?? headers['Retry-After'];
  if (raw) {
    const parsed = Number(raw);
    if (!Number.isNaN(parsed) && parsed >= 0) return parsed;
  }
  return undefined;
}

function extractContractDetails(err: unknown): Record<string, unknown> | undefined {
  const msg = getErrorMessage(err);
  const hostErrorMatch = msg.match(/Error\((\w+),\s*(\w+)\)/);
  if (hostErrorMatch) {
    return { errorType: hostErrorMatch[1], errorCode: hostErrorMatch[2] };
  }
  return undefined;
}

// ── Core mapping function ─────────────────────────────────────────────────────

/**
 * Map any exception originating from a Stellar SDK call to a
 * {@link MappedStellarError} descriptor.
 */
export function mapStellarException(err: unknown): MappedStellarError {
  if (isTimeoutError(err)) {
    return {
      code: StellarErrorCode.TIMEOUT,
      httpStatus: HttpStatus.GATEWAY_TIMEOUT,
      message: 'The Stellar network request timed out. Please try again.',
    };
  }

  if (isNotFoundError(err)) {
    return {
      code: StellarErrorCode.NOT_FOUND,
      httpStatus: HttpStatus.NOT_FOUND,
      message:
        'The requested Stellar resource was not found. Verify the account or contract ID.',
    };
  }

  if (isRateLimitError(err)) {
    return {
      code: StellarErrorCode.RATE_LIMITED,
      httpStatus: HttpStatus.TOO_MANY_REQUESTS,
      message:
        'Horizon rate limit exceeded. Please slow down your requests.',
      retryAfter: extractRetryAfter(err) ?? 60,
    };
  }

  if (isContractError(err)) {
    return {
      code: StellarErrorCode.CONTRACT_ERROR,
      httpStatus: HttpStatus.BAD_REQUEST,
      message: getErrorMessage(err) || 'A Soroban contract error occurred.',
      details: extractContractDetails(err),
    };
  }

  if (isHorizonNetworkError(err)) {
    return {
      code: StellarErrorCode.CONNECTION_ERROR,
      httpStatus: HttpStatus.BAD_GATEWAY,
      message:
        'Unable to reach the Stellar Horizon service. The network may be temporarily unavailable.',
    };
  }

  // Fallback — 500, no technical details exposed
  return {
    code: StellarErrorCode.INTERNAL,
    httpStatus: HttpStatus.INTERNAL_SERVER_ERROR,
    message: 'An unexpected Stellar error occurred. Please try again later.',
  };
}

// ── Exception factory ─────────────────────────────────────────────────────────

/**
 * Convert a Stellar SDK exception into an NestJS `HttpException` that can be
 * thrown from a service or caught by the global exception filter.
 *
 * The `traceId` is embedded in the response body so downstream clients and
 * support engineers can correlate errors.
 *
 * @param err      The original Stellar SDK error
 * @param traceId  Correlation ID from the request (e.g. X-Correlation-ID header)
 */
export function throwMappedStellarException(
  err: unknown,
  traceId?: string,
): never {
  const mapped = mapStellarException(err);

  const responseBody: Record<string, unknown> = {
    code: mapped.code,
    message: mapped.message,
    ...(traceId ? { traceId } : {}),
    ...(mapped.details ? { details: mapped.details } : {}),
  };

  switch (mapped.httpStatus) {
    case HttpStatus.NOT_FOUND:
      throw new NotFoundException(responseBody);

    case HttpStatus.TOO_MANY_REQUESTS: {
      const ex = new TooManyRequestsException(responseBody);
      // Attach Retry-After to the response object — the global filter will pick
      // it up via the standard NestJS exception pipeline.
      (ex as unknown as Record<string, unknown>)['retryAfter'] = mapped.retryAfter;
      throw ex;
    }

    case HttpStatus.BAD_REQUEST:
      throw new BadRequestException(responseBody);

    case HttpStatus.BAD_GATEWAY:
      throw new BadGatewayException(responseBody);

    case HttpStatus.GATEWAY_TIMEOUT:
      throw new GatewayTimeoutException(responseBody);

    default:
      throw new HttpException(responseBody, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
