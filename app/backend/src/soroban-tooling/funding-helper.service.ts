import { Injectable } from '@nestjs/common';

import { AppConfigService } from '../config';
import { HorizonService } from '../stellar/horizon.service';
import { FundingPreflightDto } from './dto/testnet-tooling.dto';

@Injectable()
export class FundingHelperService {
  private readonly recommendedMinimum = 5;

  constructor(
    private readonly horizonService: HorizonService,
    private readonly configService: AppConfigService,
  ) {}

  async checkFunding(dto: FundingPreflightDto) {
    const minBalanceXlm = dto.minBalanceXlm ?? this.recommendedMinimum;
    const account = await this.horizonService.getAccount(dto.accountId);

    if (!account) {
      return {
        ready: false,
        accountExists: false,
        minimumBalanceXlm: minBalanceXlm,
        currentBalanceXlm: '0',
        network: this.configService.network,
        faucetUrl: this.getFaucetUrl(),
        remediation: [
          'Create or fund the account with the Stellar testnet faucet before deploying.',
          `Retry once the account holds at least ${minBalanceXlm} XLM.`,
        ],
      };
    }

    const nativeBalance = account.balances.find(
      (balance) => balance.asset_type === 'native',
    );
    const currentBalance = Number(nativeBalance?.balance ?? '0');
    const ready = currentBalance >= minBalanceXlm;

    return {
      ready,
      accountExists: true,
      minimumBalanceXlm: minBalanceXlm,
      currentBalanceXlm: (nativeBalance?.balance ?? '0'),
      network: this.configService.network,
      faucetUrl: this.getFaucetUrl(),
      remediation: ready
        ? []
        : [
            `Fund the account until it reaches at least ${minBalanceXlm} XLM.`,
            'Use the testnet faucet link below, then rerun deploy.',
          ],
    };
  }

  private getFaucetUrl(): string {
    return this.configService.network === 'mainnet'
      ? 'https://developers.stellar.org/docs/build/apps/example-application-tutorial/fund-account'
      : 'https://laboratory.stellar.org/#account-creator?network=test';
  }
}
