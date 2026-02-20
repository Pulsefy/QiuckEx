import {
    Injectable,
    NestInterceptor,
    ExecutionContext,
    CallHandler,
  } from '@nestjs/common';
  import { Observable } from 'rxjs';
  import { tap } from 'rxjs/operators';
  import { MetricsService } from './metrics.service';
  import { Request } from 'express';
  
  @Injectable()
  export class MetricsInterceptor implements NestInterceptor {
    constructor(private metricsService: MetricsService) {}
  
    intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
        const start = Date.now();
      const req = context.switchToHttp().getRequest<Request>();
      const method = req.method;
      const route = req.route?.path || req.path;
  
      return next.handle().pipe(
        tap({
          next: () => {
            const res = context.switchToHttp().getResponse();
            const duration = (Date.now() - start) / 1000;
            this.metricsService.recordRequestDuration(
              method,
              route,
              res.statusCode,
              duration,
            );
          },
          error: (err) => {
            const duration = (Date.now() - start) / 1000;
            this.metricsService.recordRequestDuration(
              method,
              route,
              err.status || 500,
              duration,
            );
          },
        }),
      );
    }
  }