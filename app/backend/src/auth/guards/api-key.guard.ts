import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { RATE_LIMITS } from '../../common/constants/rate-limit.constants';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const apiKey = request.headers['x-api-key'];

    if (!apiKey) return true; // public access allowed

    const hashedKeys = (process.env.API_KEYS || '').split(',');

    for (const hash of hashedKeys) {
      if (await bcrypt.compare(apiKey, hash)) {
        request.apiKey = {
          rateLimit: RATE_LIMITS.API_KEY.limit,
        };
        return true;
      }
    }

    throw new UnauthorizedException({
      error: 'INVALID_API_KEY',
      message: 'API key is invalid',
    });
  }
}
