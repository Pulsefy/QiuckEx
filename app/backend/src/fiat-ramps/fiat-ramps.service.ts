import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { Keypair } from '@stellar/stellar-sdk';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import {
  Sep24InternalStatus,
  AnchorDiscoveryError,
  Sep10AuthError,
  Sep24InitiationError,
} from './types/sep24.types';
import { AnchorClientService } from './anchor-client.service';
import { AppConfigService } from '../config/app-config.service';

/** Errors that should return a 400 (client-facing, expected). */
const CLIENT_ERRORS: readonly string[] = [
  AnchorDiscoveryError.name,
  Sep24InitiationError.name,
];

function isClientError(err: unknown): boolean {
  return err instanceof Error && CLIENT_ERRORS.includes(err.name);
}

@Injectable()
export class FiatRampsService {
  private readonly logger = new Logger(FiatRampsService.name);

  constructor(
    private readonly sep24Repository: Sep24TransactionRepository,
    private readonly anchorClient: AnchorClientService,
    private readonly appConfig: AppConfigService,
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

    const {
      assetCode,
      amount,
      userAccount,
      anchorDomain,
    } = depositDto;

    try {
      // ── 1. Discover anchor capabilities from stellar.toml ──────────────
      const capabilities = await this.anchorClient.discoverAnchorCapabilities(anchorDomain);

      // Validate that the requested asset is supported by this anchor
      if (
        capabilities.supportedAssets.length > 0 &&
        !capabilities.supportedAssets.includes(assetCode.toUpperCase())
      ) {
        throw new AnchorDiscoveryError(
          anchorDomain,
          `asset ${assetCode} is not supported; supported: [${capabilities.supportedAssets.join(', ')}]`,
        );
      }

      // ── 2. Obtain SEP-10 JWT ──────────────────────────────────────────
      const keypair = this.getKeyPair();
      const jwt = await this.anchorClient.performSep10Auth(
        anchorDomain,
        capabilities.authServer,
        keypair,
        this.appConfig.stellarNetworkPassphrase,
      );

      // ── 3. Initiate SEP-24 deposit (get real interactive URL) ─────────
      const interactive = await this.anchorClient.initiateSep24Transaction({
        anchorDomain,
        jwt,
        transferServer: capabilities.transferServer,
        type: 'deposit',
        assetCode: assetCode.toUpperCase(),
        account: userAccount,
        amount: String(amount),
      });

      // Use the anchor-assigned ID when available, otherwise generate a placeholder
      const anchorTransactionId = interactive.id ?? `dep_${Date.now()}`;

      // Persist the in-flight transaction so the poller can track it
      const record = await this.sep24Repository.create({
        anchor_transaction_id: anchorTransactionId,
        anchor_domain: anchorDomain,
        type: 'deposit',
        status: Sep24InternalStatus.Initiated,
        anchor_status: null,
        stellar_tx_hash: null,
        amount: String(amount),
        asset_code: assetCode.toUpperCase(),
        asset_issuer: null,
        user_account: userAccount,
        interactive_url: interactive.url,
      });

      this.logger.log(
        `SEP-24 deposit initiated: anchor_tx=${anchorTransactionId} ` +
        `record_id=${record?.id ?? 'unknown'} url=${interactive.url}`,
      );

      return {
        status: 'success',
        transaction_id: anchorTransactionId,
        internal_id: record?.id ?? null,
        type: interactive.type,
        url: interactive.url,
        ...(interactive.message ? { message: interactive.message } : {}),
      };
    } catch (error) {
      this.logger.error(`Error initiating deposit: ${(error as Error).message}`);

      if (isClientError(error)) {
        throw new HttpException((error as Error).message, HttpStatus.BAD_REQUEST);
      }

      if (error instanceof Sep10AuthError) {
        throw new HttpException(
          `SEP-10 authentication failed: ${(error as Error).message}`,
          HttpStatus.BAD_GATEWAY,
        );
      }

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

    const {
      assetCode,
      amount,
      userAccount,
      anchorDomain,
    } = withdrawalDto;

    try {
      // ── 1. Discover anchor capabilities from stellar.toml ──────────────
      const capabilities = await this.anchorClient.discoverAnchorCapabilities(anchorDomain);

      // Validate that the requested asset is supported by this anchor
      if (
        capabilities.supportedAssets.length > 0 &&
        !capabilities.supportedAssets.includes(assetCode.toUpperCase())
      ) {
        throw new AnchorDiscoveryError(
          anchorDomain,
          `asset ${assetCode} is not supported; supported: [${capabilities.supportedAssets.join(', ')}]`,
        );
      }

      // ── 2. Obtain SEP-10 JWT ──────────────────────────────────────────
      const keypair = this.getKeyPair();
      const jwt = await this.anchorClient.performSep10Auth(
        anchorDomain,
        capabilities.authServer,
        keypair,
        this.appConfig.stellarNetworkPassphrase,
      );

      // ── 3. Initiate SEP-24 withdrawal (get real interactive URL) ───────
      const interactive = await this.anchorClient.initiateSep24Transaction({
        anchorDomain,
        jwt,
        transferServer: capabilities.transferServer,
        type: 'withdrawal',
        assetCode: assetCode.toUpperCase(),
        account: userAccount,
        amount: String(amount),
      });

      // Use the anchor-assigned ID when available, otherwise generate a placeholder
      const anchorTransactionId = interactive.id ?? `wth_${Date.now()}`;

      const record = await this.sep24Repository.create({
        anchor_transaction_id: anchorTransactionId,
        anchor_domain: anchorDomain,
        type: 'withdrawal',
        status: Sep24InternalStatus.Initiated,
        anchor_status: null,
        stellar_tx_hash: null,
        amount: String(amount),
        asset_code: assetCode.toUpperCase(),
        asset_issuer: null,
        user_account: userAccount,
        interactive_url: interactive.url,
      });

      this.logger.log(
        `SEP-24 withdrawal initiated: anchor_tx=${anchorTransactionId} ` +
        `record_id=${record?.id ?? 'unknown'} url=${interactive.url}`,
      );

      return {
        status: 'success',
        transaction_id: anchorTransactionId,
        internal_id: record?.id ?? null,
        type: interactive.type,
        url: interactive.url,
        ...(interactive.message ? { message: interactive.message } : {}),
      };
    } catch (error) {
      this.logger.error(`Error initiating withdrawal: ${(error as Error).message}`);

      if (isClientError(error)) {
        throw new HttpException((error as Error).message, HttpStatus.BAD_REQUEST);
      }

      if (error instanceof Sep10AuthError) {
        throw new HttpException(
          `SEP-10 authentication failed: ${(error as Error).message}`,
          HttpStatus.BAD_GATEWAY,
        );
      }

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

  // ─── Private helpers ──────────────────────────────────────────────────────

  /**
   * Load the Stellar signing keypair from the app configuration.
   *
   * @throws {Error} if STELLAR_SECRET_KEY is not configured.
   */
  private getKeyPair(): Keypair {
    const secretKey = this.appConfig.stellarSecretKey;
    if (!secretKey) {
      throw new Error(
        'STELLAR_SECRET_KEY is not configured — SEP-10 authentication requires a signing key',
      );
    }
    return Keypair.fromSecret(secretKey);
  }
}
