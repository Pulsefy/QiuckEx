import { Module } from '@nestjs/common';
import { FiatRampsController } from './fiat-ramps.controller';
import { FiatRampsService } from './fiat-ramps.service';
import { IdempotencyModule } from '../common/idempotency/idempotency.module';

@Module({
  imports: [IdempotencyModule],
  controllers: [FiatRampsController],
  providers: [FiatRampsService],
  exports: [FiatRampsService],
})
export class FiatRampsModule {}
