import { ThrottlerGuard } from '@nestjs/throttler';
import { ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected getLimit(context: ExecutionContext): number {
    const req = context.switchToHttp().getRequest();
    return req.apiKey?.rateLimit ?? super.getLimit(context);
  }
}
