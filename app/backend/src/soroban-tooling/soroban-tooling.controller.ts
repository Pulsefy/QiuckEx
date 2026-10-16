import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';

import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { DeploymentService } from './deployment.service';
import { FundingPreflightDto, DeploymentPlanDto } from './dto/testnet-tooling.dto';
import { DeploymentPlanResponseDto, FundingPreflightResponseDto } from './dto/soroban-tooling-response.dto';
import { FundingHelperService } from './funding-helper.service';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';

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
  @RateLimitTier("mutation")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Check whether a Stellar account is funded enough for deploy flows' })
  @ApiOkResponse({
    description: 'Account funding check details',
    type: FundingPreflightResponseDto,
  })
  preflightFunding(@Body() body: FundingPreflightDto): Promise<FundingPreflightResponseDto> {
    return this.fundingHelperService.checkFunding(body);
  }

  @Post('deployments/plan')
  @RateLimitTier("mutation")
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Plan a deterministic Soroban deployment run without submitting transactions' })
  @ApiOkResponse({
    description: 'Deterministic deployment plan',
    type: DeploymentPlanResponseDto,
  })
  planDeployment(@Body() body: DeploymentPlanDto): Promise<DeploymentPlanResponseDto> {
    return this.deploymentService.planDeployment(body);
  }
}

