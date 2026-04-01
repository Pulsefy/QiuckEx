import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { SentryService } from './sentry.service';
import { AppConfigService } from '../config';

/**
 * SentryExceptionFilter catches all unhandled exceptions,
 * reports them to Sentry with full request context (sanitised),
 * and then re-throws so the existing GlobalHttpExceptionFilter
 * can handle the HTTP response.
 *
 * This filter should be registered BEFORE GlobalHttpExceptionFilter
 * in the global filter chain so it sees exceptions first.
 */
@Catch()
export class SentryExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(SentryExceptionFilter.name);

  constructor(
    private readonly sentryService: SentryService,
    private readonly config: AppConfigService,
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<Request>();

    // Determine HTTP status for categorisation
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    // Only report server errors (5xx) and unexpected exceptions to Sentry.
    // 4xx errors are client mistakes and would generate too much noise.
    if (status >= 500 || !(exception instanceof HttpException)) {
      const requestContext = this.buildRequestContext(request);

      this.sentryService.captureException(exception, {
        ...requestContext,
        httpStatus: status,
      });

      this.logger.error(
        `[Sentry] Reported ${status} error on ${request.method} ${request.url}`,
        exception instanceof Error ? exception.stack : undefined,
      );
    }

    // Re-throw so GlobalHttpExceptionFilter handles the response
    throw exception;
  }

  /**
   * Build a sanitised request context object suitable for Sentry extras.
   * Strips all sensitive fields (authorization, keys, passwords, etc.).
   */
  private buildRequestContext(request: Request): Record<string, unknown> {
    const context: Record<string, unknown> = {
      method: request.method,
      url: request.url,
      correlationId: (request as Record<string, unknown>)['correlationId'],
      userAgent: request.headers['user-agent'],
      ip: request.ip,
    };

    // Sanitise query parameters
    if (request.query && Object.keys(request.query).length > 0) {
      context.query = this.sanitise(request.query as Record<string, unknown>);
    }

    // Sanitise request body
    if (request.body && Object.keys(request.body).length > 0) {
      context.body = this.sanitise(request.body as Record<string, unknown>);
    }

    // Add safe headers (exclude sensitive ones)
    const safeHeaders: Record<string, unknown> = {};
    const sensitiveHeaders = new Set([
      'authorization',
      'x-api-key',
      'cookie',
      'set-cookie',
    ]);

    for (const [key, value] of Object.entries(request.headers)) {
      if (!sensitiveHeaders.has(key.toLowerCase())) {
        safeHeaders[key] = value;
      }
    }
    context.headers = safeHeaders;

    return context;
  }

  /**
   * Deep-sanitise an object by redacting known sensitive field names.
   */
  private sanitise(obj: Record<string, unknown>): Record<string, unknown> {
    const sensitiveFields = new Set([
      'password',
      'token',
      'secret',
      'secretKey',
      'secret_key',
      'apiKey',
      'api_key',
      'authorization',
      'mnemonic',
      'seed',
      'private_key',
      'privateKey',
      'stellar_secret_key',
    ]);

    const sanitised: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (sensitiveFields.has(key.toLowerCase()) || sensitiveFields.has(key)) {
        sanitised[key] = '[REDACTED]';
      } else if (
        value &&
        typeof value === 'object' &&
        !Array.isArray(value)
      ) {
        sanitised[key] = this.sanitise(value as Record<string, unknown>);
      } else {
        sanitised[key] = value;
      }
    }
    return sanitised;
  }
}
