import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ContractRegistryService } from './contract-registry.service';
import {
  ContractRegistryResponseDto,
  PublishContractRegistryDto,
  RollbackContractRegistryDto,
} from './dto/contract-registry.dto';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key. Publishing requires an admin-scoped key.',
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller('contracts')
export class ContractRegistryController {
  constructor(private readonly contractRegistryService: ContractRegistryService) {}

  @Get('registry')
  @ApiOperation({
    summary: 'Fetch the authoritative contract registry for the active network',
  })
  @ApiResponse({ status: 200, type: ContractRegistryResponseDto })
  getRegistry() {
    return this.contractRegistryService.getRegistry();
  }

  @Post('registry/publish')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Publish deployment artifacts into the contract registry',
  })
  publish(@Body() body: PublishContractRegistryDto) {
    return this.contractRegistryService.publish(body, 'api');
  }

  @Post('registry/rollback')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Rollback the active registry entry for a contract to a previous version',
  })
  rollback(@Body() body: RollbackContractRegistryDto) {
    return this.contractRegistryService.rollback(body, 'api');
  }
}
