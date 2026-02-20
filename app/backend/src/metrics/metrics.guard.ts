import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MetricsGuard implements CanActivate {
  constructor(private configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const token = request.headers['x-metrics-token'];
    const validToken = this.configService.get('METRICS_ENDPOINT_TOKEN');

    if (!validToken || token !== validToken) {
      throw new UnauthorizedException('Invalid metrics token');
    }

    return true;
  }
}