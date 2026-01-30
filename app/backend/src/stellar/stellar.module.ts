import { Module } from '@nestjs/common';

import { HorizonService } from './horizon.service';
import { LinkService } from './link.service';

@Module({
  providers: [LinkService, HorizonService],
  exports: [LinkService, HorizonService],
})
export class StellarModule {}
