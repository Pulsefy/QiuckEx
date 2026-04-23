import { Controller, Get, Post, Body, Query, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { FiatRampsService } from './fiat-ramps.service';

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
  async initiateDeposit(@Body() depositDto: { assetCode: string; amount: number; userAccount: string; anchorDomain: string }) {
    return this.fiatRampsService.initiateDeposit(depositDto);
  }

  @Post('withdraw')
  @ApiOperation({ summary: 'Initiate SEP-24 hosted withdrawal flow' })
  @ApiResponse({ status: 201, description: 'Withdrawal flow initiated' })
  async initiateWithdrawal(@Body() withdrawalDto: { assetCode: string; amount: number; userAccount: string; anchorDomain: string }) {
    return this.fiatRampsService.initiateWithdrawal(withdrawalDto);
  }

  @Post('kyc/callback')
  @ApiOperation({ summary: 'Handle KYC redirects and updates' })
  async handleKycCallback(@Body() callbackData: any) {
    return this.fiatRampsService.handleKycCallback(callbackData);
  }

  @Post('transaction/status')
  @ApiOperation({ summary: 'Securely handle transaction status updates' })
  async updateTransactionStatus(@Body() statusData: any) {
    return this.fiatRampsService.updateTransactionStatus(statusData);
  }
}
