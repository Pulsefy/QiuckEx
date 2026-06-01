import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';
import { DemoService, DemoClearResult, DemoSeedResult } from './demo.service';

@ApiTags('demo')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Admin-scoped API key (required for all demo endpoints).',
  required: true,
})
@RateLimitGroupTag('authenticated')
@UseGuards(ApiKeyGuard)
@Controller('v1/demo')
export class DemoController {
  constructor(private readonly demoService: DemoService) {}

  @Post('seed')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Seed deterministic demo data (admin, testnet only)',
    description:
      'Upserts demo payment links and sample transactions into the database. ' +
      'Idempotent — safe to call repeatedly. Returns 403 when NETWORK is not "testnet".',
  })
  @ApiResponse({ status: 200, description: 'Fixtures seeded successfully.' })
  @ApiResponse({ status: 403, description: 'Not on testnet, or insufficient scope.' })
  seed(): Promise<DemoSeedResult> {
    return this.demoService.seed();
  }

  @Delete()
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Clear all demo data (admin, testnet only)',
    description:
      'Deletes only rows whose IDs match known demo fixtures. ' +
      'Returns 403 when NETWORK is not "testnet".',
  })
  @ApiResponse({ status: 200, description: 'Demo data cleared.' })
  @ApiResponse({ status: 403, description: 'Not on testnet, or insufficient scope.' })
  clear(): Promise<DemoClearResult> {
    return this.demoService.clear();
  }

  @Get('status')
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Demo seed status (admin, testnet only)',
    description: 'Reports which demo fixture IDs are currently present in the database.',
  })
  @ApiResponse({ status: 200, description: 'Current demo seed state.' })
  @ApiResponse({ status: 403, description: 'Not on testnet, or insufficient scope.' })
  status(): Promise<{
    network: string;
    seededLinks: string[];
    seededTransactions: string[];
  }> {
    return this.demoService.status();
  }
}