import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards, Req } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';

import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { DeploymentService } from './deployment.service';
import { FundingPreflightDto, DeploymentPlanDto } from './dto/testnet-tooling.dto';
import { FundingHelperService } from './funding-helper.service';
import { TestnetResetDto } from './dto/testnet-reset.dto';
import { TestnetResetService } from './testnet-reset.service';

@ApiTags('developer')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key. Deployment planning requires an admin-scoped key.',
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller('developer/testnet')
export class SorobanToolingController {
  constructor(
    private readonly fundingHelperService: FundingHelperService,
    private readonly deploymentService: DeploymentService,
    private readonly testnetResetService: TestnetResetService,
  ) {}

  @Post('funding/preflight')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Check whether a Stellar account is funded enough for deploy flows' })
  preflightFunding(@Body() body: FundingPreflightDto) {
    return this.fundingHelperService.checkFunding(body);
  }

  @Post('deployments/plan')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Plan a deterministic Soroban deployment run without submitting transactions' })
  planDeployment(@Body() body: DeploymentPlanDto) {
    return this.deploymentService.planDeployment(body);
  }

  @Post('reset')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Reset testnet-only event tables and reindex Soroban events for a ledger range' })
  async resetTestnet(@Body() body: TestnetResetDto, @Req() req: any) {
    const actor = req.apiKey?.name ?? 'unknown';
    return this.testnetResetService.resetAndReindex(actor, body.contractId, body.fromLedger, body.toLedger, body.force ?? true);
  }
}
