import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';

@ApiTags('network')
@Controller('v1/network')
export class NetworkController {
  constructor(private readonly configService: ConfigService) {}

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
}
