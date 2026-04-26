import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
  HttpException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

/**
 * LoggingInterceptor logs every HTTP request with full request context
 * while stripping sensitive fields from the body.
 *
 * Logged context includes:
 *   - HTTP method and URL
 *   - Correlation ID (from CorrelationIdMiddleware)
 *   - Response time in milliseconds
 *   - Sanitised request body (passwords, tokens, secrets removed)
 *   - Error message and status code on failure
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  /** Fields that must never appear in logs */
  private static readonly SENSITIVE_FIELDS = new Set([
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

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body, route } = request;
    const correlationId =
      (request as Record<string, unknown>)['correlationId'] || 'N/A';
    const userId = this.extractUserId(request);
    const routePath = route?.path || url;
    const now = Date.now();

    const sanitizedBody = this.sanitise(body);

    return next.handle().pipe(
      tap({
        next: () => {
          const duration = Date.now() - now;
          this.logger.log(
            JSON.stringify({
              correlationId,
              userId,
              route: routePath,
              method,
              url,
              duration: `${duration}ms`,
              body: sanitizedBody,
              status: 'success',
            }),
          );
        },
        error: (error: Error) => {
          const duration = Date.now() - now;
          const statusCode =
            error instanceof HttpException ? error.getStatus() : 500;
          this.logger.error(
            JSON.stringify({
              correlationId,
              userId,
              route: routePath,
              method,
              url,
              duration: `${duration}ms`,
              status: 'error',
              statusCode,
              errorMessage: error.message,
            }),
          );
        },
      }),
    );
  }

  /**
   * Extract user_id from request if available (from auth context, API key, etc.)
   */
  private extractUserId(request: Record<string, unknown>): string | undefined {
    // Try to get from user object (if authenticated)
    const user = request.user as { id?: string } | undefined;
    if (user?.id) {
      return user.id;
    }
    // Try to get from API key context
    const apiKey = request.apiKey as { userId?: string } | undefined;
    if (apiKey?.userId) {
      return apiKey.userId;
    }
    // Try to get from public key (Stellar wallet)
    const publicKey = request.publicKey as string | undefined;
    if (publicKey) {
      return publicKey;
    }
    return undefined;
  }

  /**
   * Deep-sanitise a body object by redacting sensitive fields.
   */
  private sanitise(
    obj: Record<string, unknown> | undefined,
  ): Record<string, unknown> | undefined {
    if (!obj || typeof obj !== 'object') return obj;

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (LoggingInterceptor.SENSITIVE_FIELDS.has(key.toLowerCase()) ||
          LoggingInterceptor.SENSITIVE_FIELDS.has(key)) {
        result[key] = '[REDACTED]';
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        result[key] = this.sanitise(value as Record<string, unknown>);
      } else {
        result[key] = value;
      }
    }
    return result;
  }
}