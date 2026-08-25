import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * MetricsGuard – access-control for the `/metrics` endpoint.
 *
 * The guard requires the caller to supply the configured secret in the
 * `X-Metrics-Token` request header.  The token is read from the
 * `METRICS_ENDPOINT_TOKEN` environment variable.
 *
 * **Important**: when `METRICS_ENDPOINT_TOKEN` is absent or empty the guard
 * rejects ALL requests (fail-closed).  This prevents accidental public
 * exposure of the metrics surface in environments where the variable has not
 * yet been configured.
 */
@Injectable()
export class MetricsGuard implements CanActivate {
  constructor(private configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const token = request.headers['x-metrics-token'];
    const validToken = this.configService.get<string>('METRICS_ENDPOINT_TOKEN');

    // Fail-closed: if no token is configured, deny all access.
    if (!validToken) {
      throw new UnauthorizedException('Metrics endpoint is not configured for external access');
    }

    if (token !== validToken) {
      throw new UnauthorizedException('Invalid metrics token');
    }

    return true;
  }
}