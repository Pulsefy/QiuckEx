import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import { Sep24InternalStatus } from './types/sep24.types';

@Injectable()
export class FiatRampsService {
  private readonly logger = new Logger(FiatRampsService.name);

  constructor(
    private readonly sep24Repository: Sep24TransactionRepository,
  ) {}

  async getAvailableAnchors(assetCode: string, country: string) {
    this.logger.log(`Fetching available anchors for ${assetCode} in ${country}`);
    return {
      status: 'success',
      data: [
        {
          id: 'moneygram',
          name: 'MoneyGram',
          domain: 'moneygram.stellar.org',
          supportedAssets: ['USDC', 'XLM'],
          type: 'cash',
        },
        {
          id: 'banxa',
          name: 'Banxa',
          domain: 'banxa.stellar.org',
          supportedAssets: ['USDC', 'EURC'],
          type: 'bank_transfer',
        },
      ],
    };
  }

  async initiateDeposit(depositDto: {
    assetCode: string;
    amount: number;
    userAccount: string;
    anchorDomain: string;
  }) {
    this.logger.log(`Initiating SEP-24 deposit flow with ${depositDto.anchorDomain}`);

    try {
      // Build mock interactive URL (real integration would use stellar-sdk toml resolver
      // + SEP-10 auth to obtain a JWT then POST /sep24/transactions/deposit/interactive)
      const anchorTransactionId = `dep_${Date.now()}`;
      const interactiveUrl =
        `https://${depositDto.anchorDomain}/sep24/interactive` +
        `?type=deposit&asset_code=${depositDto.assetCode}&account=${depositDto.userAccount}`;

      // Persist the in-flight transaction so the poller can track it
      const record = await this.sep24Repository.create({
        anchor_transaction_id: anchorTransactionId,
        anchor_domain: depositDto.anchorDomain,
        type: 'deposit',
        status: Sep24InternalStatus.Initiated,
        anchor_status: null,
        stellar_tx_hash: null,
        amount: String(depositDto.amount),
        asset_code: depositDto.assetCode,
        asset_issuer: null,
        user_account: depositDto.userAccount,
        interactive_url: interactiveUrl,
      });

      this.logger.log(
        `SEP-24 deposit initiated: anchor_tx=${anchorTransactionId} ` +
        `record_id=${record?.id ?? 'unknown'}`,
      );

      return {
        status: 'success',
        transaction_id: anchorTransactionId,
        internal_id: record?.id ?? null,
        type: 'interactive_customer_info_needed',
        url: interactiveUrl,
      };
    } catch (error) {
      this.logger.error(`Error initiating deposit: ${(error as Error).message}`);
      throw new HttpException('Failed to initiate deposit', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async initiateWithdrawal(withdrawalDto: {
    assetCode: string;
    amount: number;
    userAccount: string;
    anchorDomain: string;
  }) {
    this.logger.log(`Initiating SEP-24 withdrawal flow with ${withdrawalDto.anchorDomain}`);

    try {
      const anchorTransactionId = `wth_${Date.now()}`;
      const interactiveUrl =
        `https://${withdrawalDto.anchorDomain}/sep24/interactive` +
        `?type=withdraw&asset_code=${withdrawalDto.assetCode}&account=${withdrawalDto.userAccount}`;

      const record = await this.sep24Repository.create({
        anchor_transaction_id: anchorTransactionId,
        anchor_domain: withdrawalDto.anchorDomain,
        type: 'withdrawal',
        status: Sep24InternalStatus.Initiated,
        anchor_status: null,
        stellar_tx_hash: null,
        amount: String(withdrawalDto.amount),
        asset_code: withdrawalDto.assetCode,
        asset_issuer: null,
        user_account: withdrawalDto.userAccount,
        interactive_url: interactiveUrl,
      });

      this.logger.log(
        `SEP-24 withdrawal initiated: anchor_tx=${anchorTransactionId} ` +
        `record_id=${record?.id ?? 'unknown'}`,
      );

      return {
        status: 'success',
        transaction_id: anchorTransactionId,
        internal_id: record?.id ?? null,
        type: 'interactive_customer_info_needed',
        url: interactiveUrl,
      };
    } catch (error) {
      this.logger.error(`Error initiating withdrawal: ${(error as Error).message}`);
      throw new HttpException('Failed to initiate withdrawal', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async handleKycCallback(callbackData: unknown) {
    this.logger.log(`Received KYC callback update: ${JSON.stringify(callbackData)}`);
    return { status: 'acknowledged' };
  }

  async updateTransactionStatus(statusData: unknown) {
    this.logger.log(`Received transaction status update: ${JSON.stringify(statusData)}`);

    // If the anchor pushes a status webhook, update our record directly
    const data = statusData as Record<string, unknown>;
    const anchorTransactionId = data['id'] as string | undefined;

    if (anchorTransactionId) {
      const existing = await this.sep24Repository.findByAnchorTransactionId(anchorTransactionId);

      if (existing) {
        const status = data['status'] as string | undefined;
        if (status) {
          const anchorStatus = Sep24TransactionRepository.parseAnchorStatus(status);
          const internalStatus = Sep24TransactionRepository.toInternalStatus(anchorStatus);
          await this.sep24Repository.updateStatus(
            existing.id,
            internalStatus,
            status,
            (data['stellar_transaction_id'] as string | null) ?? existing.stellar_tx_hash,
          );

          this.logger.log(
            `Webhook status update applied for anchor_tx=${anchorTransactionId}: ` +
            `internal=${internalStatus}`,
          );
        }
      }
    }

    return { status: 'acknowledged' };
  }
}
