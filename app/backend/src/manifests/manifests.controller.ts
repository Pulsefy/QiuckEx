import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ManifestsService } from './manifests.service';
import { CompareManifestsDto, ManifestDiffResponseDto } from './dto/manifest-diff.dto';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';

@ApiTags('manifests')
@Controller('manifests')
export class ManifestsController {
  constructor(private readonly manifestsService: ManifestsService) {}

  @Post('diff')
  @RateLimitTier('mutation')
  @HttpCode(200)
  @ApiOperation({ summary: 'Compare two environment manifests' })
  @ApiOkResponse({
    description: 'Differences between base and target manifests',
    type: ManifestDiffResponseDto,
  })
  compareManifests(@Body() compareDto: CompareManifestsDto): ManifestDiffResponseDto {
    return this.manifestsService.diffManifests(
      compareDto.baseManifest,
      compareDto.targetManifest,
    );
  }
}

