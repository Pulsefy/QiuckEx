import {
  Controller,
  Get,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  ParseBoolPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { SupportBundleService } from './support-bundle.service';
import { SupportBundleDto } from './dto/support-bundle.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';

@ApiTags('Admin - Support Bundle')
@Controller('admin/support/bundle')
@UseGuards(ApiKeyGuard)
@ApiBearerAuth()
export class SupportBundleController {
  constructor(private readonly supportBundleService: SupportBundleService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Generate sanitized support bundle for debugging',
    description:
      'Generates a JSON bundle containing sanitized diagnostics including network config, ' +
      'contract registry, indexer status, checkpoints, and recent errors. All sensitive data ' +
      '(secrets, PII) is redacted. Bundle can be attached to GitHub issues for faster triage.',
  })
  @ApiQuery({
    name: 'includeRequestIds',
    type: Boolean,
    required: false,
    description:
      'Include request IDs in error logs for correlation. Default: false. ' +
      'Use true only if request IDs do not contain sensitive information.',
  })
  @ApiResponse({
    status: 200,
    description: 'Support bundle generated successfully',
    type: SupportBundleDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing API key',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient scopes (requires admin)',
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error',
  })
  async generateBundle(
    @Query('includeRequestIds', new ParseBoolPipe({ optional: true }))
    includeRequestIds = false,
  ): Promise<SupportBundleDto> {
    return this.supportBundleService.generateBundle(includeRequestIds);
  }
}
