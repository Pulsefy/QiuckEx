import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Optional,
  Param,
  Post,
  Put,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag, RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';
import { ContractRegistryService } from './contract-registry.service';
import { ContractCompatibilityService } from './contract-compatibility.service';
import {
  ContractCompatibilityFlow,
  ContractCompatibilityMetadataDto,
  ContractDeploymentItemDto,
  ContractDeploymentsResponseDto,
  ContractRegistryResponseDto,
  PublishContractRegistryDto,
  RollbackContractRegistryDto,
  UpsertContractDeploymentDto,
  ValidateWriteCompatibilityDto,
} from './dto';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key. Publishing requires an admin-scoped key.',
  required: false,
})
@RateLimitGroupTag('public')
@UseGuards(ApiKeyGuard)
// `contracts` is the canonical prefix. The three aliases below are frozen
// compatibility shims for clients already shipped against them — see
// docs/ROUTING-CONVENTIONS.md. Do not add further aliases.
@Controller(['contracts', 'api/contracts', 'mobile/contracts', 'api/mobile/contracts'])
export class ContractRegistryController {
  private readonly compatibilityService: ContractCompatibilityService;

  constructor(
    private readonly contractRegistryService: ContractRegistryService,
    @Optional() compatibilityService?: ContractCompatibilityService,
  ) {
    this.compatibilityService =
      compatibilityService ??
      new ContractCompatibilityService(this.contractRegistryService);
  }

  @Get('registry/compatibility')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Get contract compatibility metadata and flow requirements',
  })
  @ApiQuery({
    name: 'flow',
    required: false,
    enum: ['link', 'quote', 'pay_initiation'],
  })
  @ApiQuery({ name: 'contractName', required: false })
  @ApiResponse({ status: 200, type: ContractCompatibilityMetadataDto })
  getCompatibility(
    @Query('flow') flow?: ContractCompatibilityFlow,
    @Query('contractName') contractName?: string,
  ) {
    return this.compatibilityService.getCompatibilityMetadata(
      flow ?? 'pay_initiation',
      contractName ?? 'quickex',
    );
  }

  @Post('registry/compatibility/validate')
  @RateLimitTier('public-read')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Validate client contract version/schema assertions for a write flow',
  })
  @ApiResponse({ status: 200, type: ContractCompatibilityMetadataDto })
  validateCompatibility(@Body() body: ValidateWriteCompatibilityDto) {
    return this.compatibilityService.validateWriteCompatibility(body);
  }

  @Get('registry/deployments')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'List active contract deployments for the current network',
  })
  @ApiResponse({ status: 200, type: ContractDeploymentsResponseDto })
  getDeployments() {
    return this.contractRegistryService.getDeployments();
  }

  @Get('registry/deployments/:name')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Get active deployment metadata for a contract name',
  })
  @ApiResponse({ status: 200, type: ContractDeploymentItemDto })
  @ApiResponse({ status: 404, description: 'Deployment entry not found for contract name' })
  getDeploymentByName(@Param('name') name: string) {
    return this.contractRegistryService.getDeploymentByName(name);
  }

  @Get('registry')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Fetch the authoritative contract registry for the active network',
    description:
      'Returns the contract registry with an ETag header for change detection. Send If-None-Match with a prior ETag to get a 304 Not Modified response.',
  })
  @ApiResponse({ status: 200, type: ContractRegistryResponseDto })
  @ApiResponse({ status: 304, description: 'Registry unchanged since last poll' })
  async getRegistry(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const registry = await this.contractRegistryService.getRegistry();
    res.setHeader('ETag', registry.etag);
    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');

    const clientEtag = req.headers['if-none-match'];
    if (clientEtag && clientEtag === registry.etag) {
      res.status(HttpStatus.NOT_MODIFIED);
      return;
    }

    return registry;
  }

  @Post('registry/publish')
  @RateLimitTier('mutation')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Publish deployment artifacts into the contract registry',
  })
  publish(@Body() body: PublishContractRegistryDto, @Req() req: Request) {
    const actor = req.apiKey?.id ?? 'api';
    return this.contractRegistryService.publish(body, actor);
  }

  @Put('registry/deployments/:name')
  @RateLimitTier('mutation')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Upsert deployment metadata for one contract (admin only)',
  })
  @ApiResponse({ status: 200, type: ContractDeploymentItemDto })
  upsertDeployment(
    @Param('name') name: string,
    @Body() body: UpsertContractDeploymentDto,
    @Req() req: Request,
  ) {
    const actor = req.apiKey?.id ?? 'api';
    return this.contractRegistryService.upsertDeployment(
      {
        ...body,
        name,
      },
      actor,
    );
  }

  @Post('registry/rollback')
  @RateLimitTier('mutation')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Rollback the active registry entry for a contract to a previous version',
  })
  rollback(@Body() body: RollbackContractRegistryDto, @Req() req: Request) {
    const actor = req.apiKey?.id ?? 'api';
    return this.contractRegistryService.rollback(body, actor);
  }
}
