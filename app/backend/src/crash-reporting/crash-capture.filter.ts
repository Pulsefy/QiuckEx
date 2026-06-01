import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { CrashReportingService } from './crash-reporting.service';

/**
 * Global exception filter that captures crashes with redaction
 * Automatically captures unhandled exceptions when crash reporting is enabled
 */
@Catch()
export class CrashCaptureFilter implements ExceptionFilter {
  private readonly logger = new Logger(CrashCaptureFilter.name);

  constructor(private readonly crashReportingService: CrashReportingService) {}

  async catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const error =
      exception instanceof Error
        ? exception
        : new Error(String(exception));

    // Extract user ID from request (adjust based on your auth implementation)
    const userId = (request as Record<string, unknown>).user?.['id'] || (request as Record<string, unknown>).userId;

    // Capture crash report (only if user has opted in)
    try {
      const context = {
        method: request.method,
        url: request.url,
        statusCode: status,
        userAgent: request.headers['user-agent'],
        // Don't include headers or body as they may contain sensitive data
        // The redaction service will handle any sensitive data in the error message
      };

      await this.crashReportingService.captureCrash(userId, error, context);
    } catch (captureError) {
      // Don't let crash capture itself cause issues
      this.logger.error('Failed to capture crash', captureError);
    }

    // Send response
    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message:
        exception instanceof HttpException
          ? exception.message
          : 'Internal server error',
    };

    response.status(status).json(errorResponse);
  }
}
