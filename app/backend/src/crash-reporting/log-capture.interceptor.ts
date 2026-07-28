import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { CrashReportingService } from './crash-reporting.service';

/**
 * Interceptor that captures log lines for crash reporting
 * This is a lightweight interceptor that captures request/response logs
 */
@Injectable()
export class LogCaptureInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LogCaptureInterceptor.name);

  constructor(private readonly crashReportingService: CrashReportingService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const timestamp = new Date().toISOString();

    // Capture request log
    this.crashReportingService.captureLogLine(
      `[${timestamp}] ${method} ${url} - Request received`,
    );

    return next.handle().pipe(
      tap({
        next: () => {
          // Capture success log
          const responseTimestamp = new Date().toISOString();
          this.crashReportingService.captureLogLine(
            `[${responseTimestamp}] ${method} ${url} - Request completed`,
          );
        },
        error: (error) => {
          // Capture error log
          const errorTimestamp = new Date().toISOString();
          this.crashReportingService.captureLogLine(
            `[${errorTimestamp}] ${method} ${url} - Request failed: ${error.message}`,
          );
        },
      }),
    );
  }
}
