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
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body } = request;
    const now = Date.now();

    // Sanitizamos el body para no loguear passwords
    const sanitizedBody = { ...body };
    delete sanitizedBody.password;
    delete sanitizedBody.token;

    return next.handle().pipe(
      tap({
        next: () => {
          const delay = Date.now() - now;
          this.logger.log(
            `${method} ${url} ${delay}ms - Body: ${JSON.stringify(sanitizedBody)}`,
          );
        },
        error: (error: Error) => {
          const delay = Date.now() - now;
          this.logger.error(
            `${method} ${url} ${delay}ms - Error: ${error.message}`,
          );
        },
      }),
    );
  }
}