import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';

import { Network, stellarConfig } from '../config/stellar.config';
import { withSpan } from '../tracing/trace-span.util';

export interface HorizonAccountResponse {
  account_id: string;
  sequence: string;
  home_domain?: string;
  thresholds: {
    low_threshold: number;
    med_threshold: number;
    high_threshold: number;
  };
  flags: {
    auth_required: boolean;
    auth_revocable: boolean;
    auth_immutable: boolean;
    auth_clawback_enabled: boolean;
  };
  balances: Array<{
    balance: string;
    asset_type: string;
    asset_code?: string;
    asset_issuer?: string;
  }>;
  [key: string]: unknown;
}

@Injectable()
export class HorizonService {
  private readonly logger = new Logger(HorizonService.name);

  constructor(
    @Inject(stellarConfig.KEY)
    private readonly config: ConfigType<typeof stellarConfig>,
  ) {}

  getNetwork(): Network {
    return this.config.network;
  }

  getBaseUrl(): string {
    return this.config.horizonBaseUrl;
  }

  /**
   * Fetch account information from Horizon
   * @param accountId - The Stellar account ID
   * @returns Account information or null if not found
   */
  async getAccount(accountId: string): Promise<HorizonAccountResponse | null> {
    return withSpan(
      'horizon.getAccount',
      {
        'rpc.system': 'horizon',
        'server.address': this.config.horizonBaseUrl,
        'horizon.account_id': accountId,
      },
      async (span) => {
        try {
          const url = `${this.config.horizonBaseUrl}/accounts/${accountId}`;
          const response = await fetch(url, {
            headers: {
              Accept: 'application/json',
            },
          });
          span.setAttribute('http.status_code', response.status);

          if (!response.ok) {
            if (response.status === 404) {
              this.logger.debug(`Account ${accountId} not found on Horizon`);
              return null;
            }
            throw new Error(`Horizon returned ${response.status}`);
          }

          return await response.json() as HorizonAccountResponse;
        } catch (error) {
          span.recordException(error as Error);
          this.logger.warn(`Failed to fetch account ${accountId}: ${error.message}`);
          return null;
        }
      },
    );
  }
}
