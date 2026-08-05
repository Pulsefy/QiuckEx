import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiHeader,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request, Response } from 'express';

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';
import {
  ContractSpecResponseDto,
  ContractSpecsResponseDto,
  StoreContractSpecDto,
} from './dto/contract-spec.dto';
import { ContractSpecService } from './contract-spec.service';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key. Storing specs requires an admin-scoped key.',
  required: false,
})
@RateLimitGroupTag('public')
@UseGuards(ApiKeyGuard)
@Controller(['contracts', 'api/contracts', 'mobile/contracts', 'api/mobile/contracts'])
export class ContractSpecController {
  constructor(private readonly specService: ContractSpecService) {}

  @Get('specs')
  @ApiOperation({
    summary: 'Get all contract specs for the active network',
    description:
      'Returns all contract specifications with ETag header for change detection. ' +
      'Send If-None-Match with a prior ETag to get a 304 Not Modified response.',
  })
  @ApiResponse({ status: 200, type: ContractSpecsResponseDto })
  @ApiResponse({ status: 304, description: 'Specs unchanged since last poll' })
  async getAllSpecs(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const specs = await this.specService.getAllSpecs();
    res.setHeader('ETag', specs.etag);
    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');

    const clientEtag = req.headers['if-none-match'];
    if (clientEtag && clientEtag === specs.etag) {
      res.status(HttpStatus.NOT_MODIFIED);
      return;
    }

    return specs;
  }

  @Get('specs/:name')
  @ApiOperation({
    summary: 'Get contract spec for a specific contract',
    description:
      'Returns the contract specification including methods, events, and storage structures. ' +
      'Results include ETag for cache validation.',
  })
  @ApiParam({ name: 'name', description: 'Contract name (e.g., quickex)' })
  @ApiResponse({ status: 200, type: ContractSpecResponseDto })
  @ApiResponse({ status: 404, description: 'Contract spec not found' })
  @ApiResponse({ status: 304, description: 'Spec unchanged since last poll' })
  async getContractSpec(
    @Param('name') name: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const spec = await this.specService.getContractSpec(name);
    res.setHeader('ETag', spec.etag);
    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');

    const clientEtag = req.headers['if-none-match'];
    if (clientEtag && clientEtag === spec.etag) {
      res.status(HttpStatus.NOT_MODIFIED);
      return;
    }

    return spec;
  }

  @Post('specs')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Store or update contract specification',
    description:
      'Store the contract ABI/specification in the registry. Requires admin scope.',
  })
  @ApiResponse({ status: 200, type: ContractSpecResponseDto })
  @ApiResponse({ status: 400, description: 'Contract not registered or invalid spec' })
  async storeSpec(
    @Body() body: StoreContractSpecDto,
    @Req() req: Request,
  ) {
    const actor = req.apiKey?.id ?? 'api';
    return this.specService.storeContractSpec(body, actor);
  }

  @Put('specs/:name')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Update contract specification',
    description:
      'Update the contract specification for a specific contract. Requires admin scope.',
  })
  @ApiParam({ name: 'name', description: 'Contract name (e.g., quickex)' })
  @ApiResponse({ status: 200, type: ContractSpecResponseDto })
  @ApiResponse({ status: 404, description: 'Contract spec not found' })
  @ApiResponse({ status: 400, description: 'Invalid spec data' })
  async updateSpec(
    @Param('name') name: string,
    @Body() body: StoreContractSpecDto,
    @Req() req: Request,
  ) {
    const actor = req.apiKey?.id ?? 'api';
    return this.specService.storeContractSpec(
      {
        ...body,
        name,
      },
      actor,
    );
  }
}