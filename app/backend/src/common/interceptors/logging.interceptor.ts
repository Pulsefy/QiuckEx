import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  
  private readonly logger = new Logger('HTTP');

  private readonly sensitiveFields = [
    'apiKey',
    'password',
    'token',
    'secret',
    'privateKey',
  ];

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body } = request;
    const requestId = request['correlationId'];
    const now = Date.now();

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse();
        const delay = Date.now() - now;
        const statusCode = response.statusCode;

        
        const sanitizedBody = this.sanitize(body);

        
        const message = `${method} ${url} ${statusCode} - ${delay}ms`;

        
        this.logger.log({
          message,
          requestId,
          body: sanitizedBody,
        });
      }),
    );
  }

  private sanitize(data: any) {
    if (!data || typeof data !== 'object') return data;
    const cleanData = { ...data };

    this.sensitiveFields.forEach((field) => {
      if (field in cleanData) {
        cleanData[field] = '[REDACTED]';
      }
    });
    return cleanData;
  }
}