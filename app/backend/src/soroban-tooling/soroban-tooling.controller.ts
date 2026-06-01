import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';

import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { DeploymentService } from './deployment.service';
import { FundingPreflightDto, DeploymentPlanDto } from './dto/testnet-tooling.dto';
import { FundingHelperService } from './funding-helper.service';

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
}
