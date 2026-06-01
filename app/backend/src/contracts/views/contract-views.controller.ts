import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import {
  ApiHeader,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ApiKeyGuard } from '../../auth/guards/api-key.guard';
import { RateLimitGroupTag } from '../../auth/decorators/rate-limit-group.decorator';
import {
  ContractViewsService,
  type ContractMetadataView,
  type EscrowSummaryView,
  type FeeConfigView,
  type LinkSummaryView,
  type PauseStateView,
} from './contract-views.service';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key for higher rate limits.',
  required: false,
})
@RateLimitGroupTag('public')
@UseGuards(ApiKeyGuard)
@Controller('v1/contracts/views')
export class ContractViewsController {
  constructor(private readonly views: ContractViewsService) {}

  @Get('fee-config')
  @ApiOperation({
    summary: 'Current fee configuration',
    description:
      'Returns the fee basis points, fee recipient address, and minimum fee ' +
      'currently set on the contract.  Results are cached for 15 s.',
  })
  @ApiResponse({ status: 200, description: 'Fee configuration.' })
  getFeeConfig(): Promise<FeeConfigView> {
    return this.views.getFeeConfig();
  }

  @Get('pause-state')
  @ApiOperation({
    summary: 'Contract pause state',
    description:
      'Returns whether the contract is currently paused and, if so, the ledger ' +
      'at which it was paused.  Results are cached for 15 s.',
  })
  @ApiResponse({ status: 200, description: 'Pause state.' })
  getPauseState(): Promise<PauseStateView> {
    return this.views.getPauseState();
  }

  @Get('metadata')
  @ApiOperation({
    summary: 'Contract metadata',
    description:
      'Returns the contract name, version, network, and deploy ledger.  Safe to ' +
      'call on page load for a sanity-check against expected contract config.',
  })
  @ApiResponse({ status: 200, description: 'Contract metadata.' })
  getMetadata(): Promise<ContractMetadataView> {
    return this.views.getContractMetadata();
  }

  @Get('escrow/:id')
  @ApiOperation({
    summary: 'Escrow summary by ID',
    description:
      'Fetches the current on-chain state of a single escrow record.  Includes ' +
      'expiry status so the UI can render "expired" without a separate ledger lookup.',
  })
  @ApiParam({ name: 'id', description: 'On-chain escrow identifier' })
  @ApiResponse({ status: 200, description: 'Escrow summary.' })
  @ApiResponse({ status: 404, description: 'Escrow not found or TTL expired.' })
  getEscrow(@Param('id') id: string): Promise<EscrowSummaryView> {
    return this.views.getEscrowSummary(id);
  }

  @Get('link/:identifier')
  @ApiOperation({
    summary: 'Payment link summary by slug or ID',
    description:
      'Returns the on-chain summary for a payment link so the UI can render ' +
      'amount, asset, and active state without hitting the indexer.',
  })
  @ApiParam({ name: 'identifier', description: 'Link slug or on-chain ID' })
  @ApiResponse({ status: 200, description: 'Link summary.' })
  @ApiResponse({ status: 404, description: 'Link not found or TTL expired.' })
  getLink(@Param('identifier') identifier: string): Promise<LinkSummaryView> {
    return this.views.getLinkSummary(identifier);
  }
}