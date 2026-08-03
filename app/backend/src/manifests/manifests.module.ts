import { Module } from '@nestjs/common';
import { ManifestsService } from './manifests.service';
import { ManifestsController } from './manifests.controller';

@Module({
  controllers: [ManifestsController],
  providers: [ManifestsService],
})
export class ManifestsModule {}
