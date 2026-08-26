import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  BadRequestException,
  BadGatewayException,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { FiatRampsService } from './fiat-ramps.service';
import {
  AnchorNotFoundError,
  FiatRampsConfigurationError,
  Sep10AuthError,
  Sep24InitiationError,
  UnsupportedAssetError,
} from './errors';

@ApiTags('fiat-ramps')
@Controller('fiat-ramps')
export class FiatRampsController {
  constructor(private readonly fiatRampsService: FiatRampsService) {}

  @Get('anchors')
  @ApiOperation({ summary: 'Fetch available anchors based on user location/asset' })
  @ApiResponse({ status: 200, description: 'List of available anchors' })
  async getAvailableAnchors(@Query('assetCode') assetCode: string, @Query('country') country: string) {
    return this.fiatRampsService.getAvailableAnchors(assetCode, country);
  }

  @Post('deposit')
  @ApiOperation({ summary: 'Initiate SEP-24 hosted deposit flow' })
  @ApiResponse({ status: 201, description: 'Deposit flow initiated' })
  @ApiResponse({ status: 400, description: 'Asset not supported by the anchor' })
  @ApiResponse({ status: 401, description: 'SEP-10 authentication with the anchor failed' })
  @ApiResponse({ status: 404, description: 'Anchor could not be discovered (stellar.toml unreachable or misconfigured)' })
  @ApiResponse({ status: 502, description: 'SEP-24 interactive initiation failed' })
  async initiateDeposit(@Body() depositDto: { assetCode: string; amount: number; userAccount: string; anchorDomain: string }) {
    try {
      return await this.fiatRampsService.initiateDeposit(depositDto);
    } catch (err) {
      this.mapFiatRampError(err);
    }
  }

  @Post('withdraw')
  @ApiOperation({ summary: 'Initiate SEP-24 hosted withdrawal flow' })
  @ApiResponse({ status: 201, description: 'Withdrawal flow initiated' })
  @ApiResponse({ status: 400, description: 'Asset not supported by the anchor' })
  @ApiResponse({ status: 401, description: 'SEP-10 authentication with the anchor failed' })
  @ApiResponse({ status: 404, description: 'Anchor could not be discovered (stellar.toml unreachable or misconfigured)' })
  @ApiResponse({ status: 502, description: 'SEP-24 interactive initiation failed' })
  async initiateWithdrawal(@Body() withdrawalDto: { assetCode: string; amount: number; userAccount: string; anchorDomain: string }) {
    try {
      return await this.fiatRampsService.initiateWithdrawal(withdrawalDto);
    } catch (err) {
      this.mapFiatRampError(err);
    }
  }

  @Post('kyc/callback')
  @ApiOperation({ summary: 'Handle KYC redirects and updates' })
  async handleKycCallback(@Body() callbackData: unknown) {
    return this.fiatRampsService.handleKycCallback(callbackData);
  }

  @Post('transaction/status')
  @ApiOperation({ summary: 'Securely handle transaction status updates' })
  async updateTransactionStatus(@Body() statusData: unknown) {
    return this.fiatRampsService.updateTransactionStatus(statusData);
  }

  /**
   * Map handshake failures to stable HTTP responses with deterministic
   * error codes. Re-throws anything that is not a fiat-ramp typed error.
   */
  private mapFiatRampError(err: unknown): never {
    if (err instanceof AnchorNotFoundError) {
      throw new NotFoundException({
        code: 'ANCHOR_NOT_FOUND',
        message: err.message,
      });
    }
    if (err instanceof UnsupportedAssetError) {
      throw new BadRequestException({
        code: 'UNSUPPORTED_ASSET',
        message: err.message,
      });
    }
    if (err instanceof Sep10AuthError) {
      throw new UnauthorizedException({
        code: 'SEP10_AUTH_FAILED',
        message: err.message,
      });
    }
    if (err instanceof Sep24InitiationError) {
      throw new BadGatewayException({
        code: 'SEP24_INITIATION_FAILED',
        message: err.message,
      });
    }
    if (err instanceof FiatRampsConfigurationError) {
      throw new InternalServerErrorException({
        code: 'FIAT_RAMPS_CONFIGURATION',
        message: err.message,
      });
    }
    throw err;
  }
}
