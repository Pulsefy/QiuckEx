import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected async handleRequest(
    context: ExecutionContext,
    limit: number,
    ttl: number,
  ): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    // Dynamic rate limit per API key
    const dynamicLimit = req.apiKey?.rateLimit ?? limit;

    return super.handleRequest(context, dynamicLimit, ttl);
  }
}
