import { Module } from '@nestjs/common';
import { FiatRampsController } from './fiat-ramps.controller';
import { FiatRampsService } from './fiat-ramps.service';

@Module({
  controllers: [FiatRampsController],
  providers: [FiatRampsService],
  exports: [FiatRampsService],
})
export class FiatRampsModule {}
