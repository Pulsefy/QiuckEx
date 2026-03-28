import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiKeysService } from '../../api-keys/api-keys.service';
import { ApiKeyScope } from '../../api-keys/api-keys.types';
import { RATE_LIMITS } from '../../common/constants/rate-limit.constants';
import { REQUIRED_SCOPES_KEY } from '../decorators/require-scopes.decorator';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly apiKeysService: ApiKeysService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const rawKey: string | undefined = request.headers['x-api-key'];

    if (!rawKey) return true; // public access allowed

    const result = await this.apiKeysService.validateKey(rawKey);

    if (!result) {
      throw new UnauthorizedException({
        error: 'INVALID_API_KEY',
        message: 'API key is invalid',
      });
    }

    const { record, hasScope } = result;

    if (this.apiKeysService.isOverQuota(record)) {
      throw new ForbiddenException({
        error: 'QUOTA_EXCEEDED',
        message: 'Monthly request quota exceeded',
      });
    }

    // Check required scopes declared on the handler/controller via @RequireScopes()
    const requiredScopes =
      this.reflector.getAllAndOverride<ApiKeyScope[]>(REQUIRED_SCOPES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];

    for (const scope of requiredScopes) {
      if (!hasScope(scope)) {
        throw new ForbiddenException({
          error: 'INSUFFICIENT_SCOPE',
          message: `API key missing required scope: ${scope}`,
        });
      }
    }

    request.apiKey = {
      id: record.id,
      name: record.name,
      scopes: record.scopes,
      rateLimit: RATE_LIMITS.API_KEY.limit,
    };

    return true;
  }
}
