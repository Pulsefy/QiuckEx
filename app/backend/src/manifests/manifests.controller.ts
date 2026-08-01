import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { ManifestsService } from './manifests.service';
import { CompareManifestsDto } from './dto/manifest-diff.dto';

@Controller('manifests')
export class ManifestsController {
  constructor(private readonly manifestsService: ManifestsService) {}

  @Post('diff')
  @HttpCode(200)
  compareManifests(@Body() compareDto: CompareManifestsDto) {
    return this.manifestsService.diffManifests(
      compareDto.baseManifest,
      compareDto.targetManifest,
    );
  }
}
