import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { AppConfigService } from './app-config.service';
import { BootstrapResponseDto } from './bootstrap.dto';

@ApiTags('network')
@Controller('v1/network')
export class NetworkController {
  constructor(
    private readonly configService: ConfigService,
    private readonly appConfigService: AppConfigService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Read-only network runtime configuration',
    description:
      'Returns active Stellar network and public endpoints for client sanity checks.',
  })
  getNetworkConfig() {
    const stellarConfig = this.configService.get<{
      network: 'testnet' | 'mainnet';
      networkPassphrase: string;
      horizonBaseUrl: string;
      sorobanRpcUrl: string;
      explorerUrl: string;
    }>('stellar');

    return {
      network: stellarConfig?.network,
      passphrase: stellarConfig?.networkPassphrase,
      horizonUrl: stellarConfig?.horizonBaseUrl,
      sorobanRpcUrl: stellarConfig?.sorobanRpcUrl,
      explorerUrl: stellarConfig?.explorerUrl,
    };
  }

  @Get('bootstrap')
  @ApiOperation({
    summary: 'Get application bootstrap configuration',
    description:
      'Returns runtime configuration for the frontend to bootstrap environment-specific settings (network, contracts, metadata).',
  })
  @ApiResponse({
    status: 200,
    description: 'Successful retrieval of bootstrap payload',
    type: BootstrapResponseDto,
  })
  getBootstrapConfig(): BootstrapResponseDto {
    const base = this.appConfigService.getBootstrapBase();
    
    let featureFlags = {};
    const flagsJson = this.appConfigService.featureFlagsBootstrapJson;
    
    if (flagsJson) {
      try {
        featureFlags = JSON.parse(flagsJson);
      } catch (error) {
        console.warn('Failed to parse FEATURE_FLAGS_BOOTSTRAP_JSON', error);
      }
    }

    return {
      network: base.network,
      contracts: base.contracts,
      backendMetadata: {
        ...base.backendMetadata,
        featureFlags,
      },
    };
  }
}