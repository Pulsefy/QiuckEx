import {
  Body,
  Controller,
  Get,
  Post,
  HttpCode,
  HttpStatus,
  UseGuards,
  Logger,
} from '@nestjs/common';
import {
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';
import {
  SeedResetOptionsDto,
  SeedResetReportDto,
  SeedResetStatusDto,
} from './dto/seed-reset.dto';
import { SeedResetScheduler } from './seed-reset.scheduler';
import { DemoService } from './demo.service';
import { DemoSeedResult, DemoClearResult } from './demo.service';

@ApiTags('seed-reset')
@ApiHeader({
  name: 'X-API-Key',
  description: 'API key with admin scope for reset operations',
  required: false,
})
@RateLimitGroupTag('authenticated')
@UseGuards(ApiKeyGuard)
@Controller(['seed-reset', 'api/seed-reset'])
export class SeedResetController {
  private readonly logger = new Logger(SeedResetController.name);

  constructor(
    private readonly scheduler: SeedResetScheduler,
    private readonly demoService: DemoService,
  ) {}

  @Post('trigger')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Trigger a manual seed reset',
    description:
      'Manually triggers a seed reset. Requires admin scope.\n' +
      'Options include force flag, table exclusions, and preservation options.',
  })
  @ApiResponse({ status: 200, type: SeedResetReportDto })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiResponse({ status: 503, description: 'Service unavailable' })
  async triggerReset(@Body() options: SeedResetOptionsDto = {}): Promise<SeedResetReportDto> {
    this.logger.log('Manual seed reset triggered via API');
    return this.scheduler.manualReset(options);
  }

  @Post('force')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Force a seed reset bypassing exclusions',
    description:
      'Forces a seed reset even if exclusions would normally prevent it. ' +
      'Use with caution. Requires admin scope.',
  })
  @ApiResponse({ status: 200, type: SeedResetReportDto })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async forceReset(@Body() options: SeedResetOptionsDto = {}): Promise<SeedResetReportDto> {
    this.logger.warn('Force seed reset triggered via API');
    return this.scheduler.forceReset(options);
  }

  @Get('status')
  @RequireScopes('admin', 'read')
  @ApiOperation({
    summary: 'Get seed reset scheduler status',
    description:
      'Returns current status of the seed reset scheduler including:\n' +
      '- Enabled/disabled state\n' +
      '- Last reset time\n' +
      '- Success/failure counts\n' +
      '- Active exclusions\n' +
      '- Next scheduled run',
  })
  @ApiResponse({ status: 200, type: SeedResetStatusDto })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async getStatus(): Promise<SeedResetStatusDto> {
    return this.scheduler.getStatus();
  }

  @Get('running')
  @RequireScopes('admin', 'read')
  @ApiOperation({
    summary: 'Check if a reset is currently running',
    description: 'Returns whether a seed reset is currently in progress.',
  })
  @ApiResponse({ status: 200, schema: { example: { running: false } } })
  async isRunning(): Promise<{ running: boolean }> {
    return { running: this.scheduler.isRunning() };
  }

  @Post('seed')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Seed demo data without clearing first',
    description: 'Upserts demo data into the database without clearing existing data. ' +
      'Idempotent operation. Requires admin scope.',
  })
  @ApiResponse({ status: 200, type: Object })
  async seed(): Promise<DemoSeedResult> {
    this.logger.log('Manual seed triggered via API');
    return this.demoService.seed();
  }

  @Post('clear')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Clear all demo data',
    description: 'Removes all demo data from the database. ' +
      'Requires admin scope. Use with caution.',
  })
  @ApiResponse({ status: 200, type: Object })
  async clear(): Promise<DemoClearResult> {
    this.logger.warn('Manual clear triggered via API');
    return this.demoService.clear();
  }

  @Get('status/data')
  @RequireScopes('admin', 'read')
  @ApiOperation({
    summary: 'Get current demo data status',
    description:
      'Returns which demo fixtures are currently present in the database.',
  })
  @ApiResponse({ status: 200, type: Object })
  async getDataStatus() {
    return this.demoService.status();
  }
}