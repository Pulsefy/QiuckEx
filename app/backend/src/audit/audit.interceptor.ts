import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { AuditService } from './audit.service';

/**
 * Interceptor to emit audit logs from critical code paths automatically.
 * Apply this to controllers or specific routes via @UseInterceptors(AuditInterceptor)
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly auditService: AuditService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, user, headers } = request;
    
    // Fallback info if not fully authenticated or request ID is missing
    const actor = user?.id || user?.email || 'anonymous';
    const requestId = headers['x-request-id'] || 'unknown';

    return next.handle().pipe(
      tap(() => {
        // Log successful actions
        // Action names can be customized via metadata in a full implementation
        const action = `${method} ${url}`;
        this.auditService.log(
          actor,
          action,
          url,
          { method },
          requestId
        );
      }),
    );
  }
}
