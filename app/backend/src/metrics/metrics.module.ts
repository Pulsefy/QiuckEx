import { Module } from '@nestjs/common';
import { MetricsController } from './metrics.controller';
import { MetricsService } from './metrics.service';
import { MetricsGuard } from './metrics.guard'; // If you created it


@Module({
  imports: [], 
  controllers: [MetricsController],
  providers: [MetricsService, MetricsGuard],
  exports: [MetricsService],
})
export class MetricsModule {}

