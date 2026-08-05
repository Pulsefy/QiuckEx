import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ContractAllowlistService } from './contract-allowlist.service';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Admin-scoped API key required to inspect the active allowlist ruleset.',
  required: true,
})
@UseGuards(ApiKeyGuard)
@Controller('contracts')
export class ContractAllowlistController {
  constructor(private readonly allowlist: ContractAllowlistService) {}

  @Get('allowlist')
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Inspect the active contract method allowlist ruleset',
  })
  @ApiResponse({ status: 200, description: 'Active allowlist mode and rules' })
  getAllowlist() {
    return this.allowlist.getState();
  }
}
