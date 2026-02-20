import { Controller, Get, UseGuards, InternalServerErrorException } from '@nestjs/common';
import { MetricsService } from './metrics.service';
import { MetricsGuard } from './metrics.guard';

@Controller('metrics')
export class MetricsController {
  constructor(private metricsService: MetricsService) {}

  @Get()
  @UseGuards(MetricsGuard)
  async getMetrics(): Promise<string> {
    try {
      const registry = this.metricsService.getRegistry();
      
      if (!registry) {
        throw new InternalServerErrorException('Metrics registry not initialized');
      }
      
      if (typeof registry.metrics !== 'function') {
        throw new InternalServerErrorException('Metrics method not available');
      }
      
      return await registry.metrics();
    } catch (error) {
      if (error instanceof InternalServerErrorException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to retrieve metrics');
    }
  }

  @Get('content-type')
  getContentType(): { type: string } {
    try {
      const registry = this.metricsService.getRegistry();
      
      if (!registry) {
        return { type: undefined };
      }
      
      return { type: registry.contentType };
    } catch (error) {
      throw error; 
    }
  }
}

