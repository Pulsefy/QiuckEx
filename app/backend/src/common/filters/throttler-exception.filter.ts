import { Catch, ExceptionFilter } from '@nestjs/common';
import { ThrottlerException } from '@nestjs/throttler';

@Catch(ThrottlerException)
export class ThrottlerExceptionFilter implements ExceptionFilter {
  catch(_: ThrottlerException, host) {
    const res = host.switchToHttp().getResponse();

    res.status(429).json({
      statusCode: 429,
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please try again later.',
    });
  }
}
