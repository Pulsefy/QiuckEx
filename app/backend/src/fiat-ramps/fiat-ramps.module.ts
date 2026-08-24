import { Module } from '@nestjs/common';
import { FiatRampsController } from './fiat-ramps.controller';
import { FiatRampsService } from './fiat-ramps.service';
import { TomlFetcherService } from '../asset-metadata/toml-fetcher.service';
import { AppConfigService } from '../config/app-config.service';

@Module({
  controllers: [FiatRampsController],
  providers: [FiatRampsService, TomlFetcherService, AppConfigService],
  exports: [FiatRampsService],
})
export class FiatRampsModule {}
