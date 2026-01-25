import { Controller, Get, Version } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get()
  @Version('1')
  getHealth() {
    return { status: 'ok' };
  }
}
