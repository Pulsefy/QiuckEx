import { Injectable } from '@nestjs/common';
import {
  ThrottlerGuard,
  ThrottlerRequest,
} from '@nestjs/throttler';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    const { context, limit } = requestProps;
    const req = context.switchToHttp().getRequest();

    const dynamicLimit = req.apiKey?.rateLimit ?? limit;

    return super.handleRequest({
      ...requestProps,
      limit: dynamicLimit,
    });
  }
}
