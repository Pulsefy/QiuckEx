import { Injectable, Logger, Optional, Inject } from '@nestjs/common';
import {
  Keypair,
  StellarToml,
  TransactionBuilder,
  WebAuth,
} from '@stellar/stellar-sdk';

import { AppConfigService } from '../config/app-config.service';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import { Sep24InternalStatus } from './types/sep24.types';
import {
  AnchorNotFoundError,
  FiatRampsConfigurationError,
  Sep10AuthError,
  Sep24InitiationError,
  UnsupportedAssetError,
} from './errors';

/**
 * Injection token for overriding handshake options (used by tests to allow
 * plain-HTTP resolution of a local stub anchor). When omitted, production
 * defaults apply.
 */
export const FIAT_RAMPS_SERVICE_OPTIONS = Symbol('FIAT_RAMPS_SERVICE_OPTIONS');

export interface FiatRampsServiceOptions {
  /**
   * Allow resolving stellar.toml over plain HTTP. Must remain false in
   * production; enabled only for local stub-anchor tests.
   */
  allowHttp?: boolean;
  /** Timeout (ms) for stellar.toml resolution. */
  tomlTimeoutMs?: number;
}

export type Sep24Operation = 'deposit' | 'withdraw';

export interface InitiateFiatRampDto {
  assetCode: string;
  amount: number;
  userAccount: string;
  anchorDomain: string;
}

export interface Sep24InteractiveResult {
  status: string;
  transaction_id: string;
  internal_id: string | null;
  type: string;
  url: string;
}

/**
 * Anchor capabilities discovered from stellar.toml (SEP-01).
 */
interface DiscoveredAnchor {
  toml: StellarToml.Api.StellarToml;
  webAuthUrl: string;
  transferServerUrl: string;
  /** WEB_AUTH_DOMAIN from stellar.toml, falling back to the home domain. */
  webAuthDomain: string;
}

const DEFAULT_TOML_TIMEOUT_MS = 5000;

@Injectable()
export class FiatRampsService {
  private readonly logger = new Logger(FiatRampsService.name);

  constructor(
    private readonly sep24Repository: Sep24TransactionRepository,
    private readonly config: AppConfigService,
    @Optional() @Inject(FIAT_RAMPS_SERVICE_OPTIONS)
    private readonly options?: FiatRampsServiceOptions,
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

  /**
   * Initiate a SEP-24 hosted deposit: discover the anchor via stellar.toml
   * (SEP-01), authenticate with SEP-10, then start the interactive flow and
   * return the anchor-provided interactive URL.
   */
  async initiateDeposit(depositDto: InitiateFiatRampDto): Promise<Sep24InteractiveResult> {
    return this.initiateInteractiveFlow('deposit', depositDto);
  }

  /**
   * Initiate a SEP-24 hosted withdrawal: discover the anchor via stellar.toml
   * (SEP-01), authenticate with SEP-10, then start the interactive flow and
   * return the anchor-provided interactive URL.
   */
  async initiateWithdrawal(withdrawalDto: InitiateFiatRampDto): Promise<Sep24InteractiveResult> {
    return this.initiateInteractiveFlow('withdraw', withdrawalDto);
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

  // ─── SEP-24 handshake ──────────────────────────────────────────────────────

  /**
   * Full SEP-24 handshake shared by deposits and withdrawals:
   *
   * 1. SEP-01  — resolve the anchor's stellar.toml, extract SEP-10/SEP-24
   *              endpoints, and verify the requested asset is supported.
   * 2. SEP-10  — obtain a challenge from the anchor, sign it with the backend
   *              keypair, and exchange it for a JWT.
   * 3. SEP-24  — POST to /deposit/interactive (or /withdraw/interactive) with
   *              the JWT and return the interactive URL from the response.
   *
   * The initiated transaction is persisted via {@link Sep24TransactionRepository}
   * so the SEP-24 polling worker can track it through to completion.
   */
  private async initiateInteractiveFlow(
    operation: Sep24Operation,
    dto: InitiateFiatRampDto,
  ): Promise<Sep24InteractiveResult> {
    const { assetCode, amount, userAccount, anchorDomain } = dto;

    this.logger.log(
      `Initiating SEP-24 ${operation} flow with ${anchorDomain} (asset=${assetCode})`,
    );

    const anchor = await this.discoverAnchor(anchorDomain);
    this.assertAssetSupported(anchorDomain, assetCode, anchor);

    const jwt = await this.authenticateSep10(anchorDomain, anchor);

    const interactive = await this.initiateSep24(
      operation,
      anchorDomain,
      anchor,
      assetCode,
      amount,
      userAccount,
      jwt,
    );

    // The anchor-assigned transaction id (falling back to a local id when the
    // anchor response does not include one) is what the polling worker uses to
    // query SEP-24 GET /transaction.
    const anchorTransactionId =
      interactive.id ?? `${operation === 'deposit' ? 'dep' : 'wth'}_${Date.now()}`;
    const interactiveUrl = interactive.url;

    const record = await this.sep24Repository.create({
      anchor_transaction_id: anchorTransactionId,
      anchor_domain: anchorDomain,
      type: operation === 'deposit' ? 'deposit' : 'withdrawal',
      status: Sep24InternalStatus.Initiated,
      anchor_status: null,
      stellar_tx_hash: null,
      amount: String(amount),
      asset_code: assetCode,
      asset_issuer: null,
      user_account: userAccount,
      interactive_url: interactiveUrl,
    });

    this.logger.log(
      `SEP-24 ${operation} initiated: anchor_tx=${anchorTransactionId} ` +
        `record_id=${record?.id ?? 'unknown'}`,
    );

    return {
      status: 'success',
      transaction_id: anchorTransactionId,
      internal_id: record?.id ?? null,
      type: interactive.type ?? 'interactive_customer_info_needed',
      url: interactiveUrl,
    };
  }

  // ─── SEP-01: anchor discovery ─────────────────────────────────────────────

  /**
   * Resolve and validate the anchor's stellar.toml for the given domain.
   * Throws {@link AnchorNotFoundError} when the TOML cannot be fetched/parsed
   * or when required SEP-10/SEP-24 endpoints are missing.
   */
  private async discoverAnchor(domain: string): Promise<DiscoveredAnchor> {
    let toml: StellarToml.Api.StellarToml;
    try {
      toml = await StellarToml.Resolver.resolve(domain, {
        allowHttp: this.options?.allowHttp ?? false,
        timeout: this.options?.tomlTimeoutMs ?? DEFAULT_TOML_TIMEOUT_MS,
      });
    } catch (err) {
      this.logger.warn(
        `stellar.toml resolution failed for ${domain}: ${(err as Error).message}`,
      );
      throw new AnchorNotFoundError(domain);
    }

    const webAuthUrl = toml.WEB_AUTH_ENDPOINT;
    const transferServerUrl = toml.TRANSFER_SERVER_SEP0024;

    if (!webAuthUrl || !transferServerUrl) {
      throw new AnchorNotFoundError(
        domain,
        `Anchor "${domain}" is misconfigured: stellar.toml must declare WEB_AUTH_ENDPOINT and TRANSFER_SERVER_SEP0024.`,
      );
    }

    return {
      toml,
      webAuthUrl,
      transferServerUrl,
      // Per SEP-10, WEB_AUTH_DOMAIN falls back to the home domain when absent.
      // The SDK type omits WEB_AUTH_DOMAIN, so it surfaces via the index
      // signature as `unknown`.
      webAuthDomain: (toml.WEB_AUTH_DOMAIN as string | undefined) || domain,
    };
  }

  /**
   * Verify the requested asset is listed in the anchor's stellar.toml
   * CURRENCIES. Throws {@link UnsupportedAssetError} otherwise.
   */
  private assertAssetSupported(
    domain: string,
    assetCode: string,
    anchor: DiscoveredAnchor,
  ): void {
    const normalizedCode = assetCode.trim().toUpperCase();
    const supported = (anchor.toml.CURRENCIES ?? []).some(
      (currency) => currency.code?.toUpperCase() === normalizedCode,
    );

    if (!supported) {
      throw new UnsupportedAssetError(normalizedCode, domain);
    }
  }

  // ─── SEP-10: authentication ───────────────────────────────────────────────

  /**
   * Complete the SEP-10 web-authentication flow against the anchor:
   *
   * 1. POST { account } to WEB_AUTH_ENDPOINT to request a challenge.
   * 2. Verify the challenge (signed by the anchor's SIGNING_KEY) and sign it
   *    with the backend keypair.
   * 3. POST { transaction } back to obtain the JWT token.
   */
  private async authenticateSep10(
    domain: string,
    anchor: DiscoveredAnchor,
  ): Promise<string> {
    const secretKey = this.config.stellarSecretKey;
    const publicKey = this.config.stellarPublicKey;

    if (!secretKey || !publicKey) {
      throw new FiatRampsConfigurationError(
        'STELLAR_SECRET_KEY and STELLAR_PUBLIC_KEY must be configured to authenticate with anchors via SEP-10.',
      );
    }

    const signingKey = anchor.toml.SIGNING_KEY;
    if (!signingKey) {
      throw new Sep10AuthError(
        domain,
        'challenge_parse',
        `Anchor "${domain}" stellar.toml does not declare a SIGNING_KEY, so the SEP-10 challenge cannot be verified.`,
      );
    }

    // 1. Request the challenge transaction.
    let challengeXdr: string;
    try {
      const challengeRes = await fetch(anchor.webAuthUrl, {
        method: 'POST',
        headers: this.sep10Headers(),
        body: new URLSearchParams({ account: publicKey }).toString(),
      });
      if (!challengeRes.ok) {
        throw new Error(`anchor returned HTTP ${challengeRes.status}`);
      }
      const challengePayload = (await challengeRes.json()) as {
        transaction?: string;
      };
      if (!challengePayload.transaction) {
        throw new Error('response did not include a challenge transaction');
      }
      challengeXdr = challengePayload.transaction;
    } catch (err) {
      this.logger.warn(
        `SEP-10 challenge request failed for ${domain}: ${(err as Error).message}`,
      );
      throw new Sep10AuthError(
        domain,
        'challenge_request',
        `Unable to obtain a SEP-10 challenge from anchor "${domain}": ${(err as Error).message}`,
      );
    }

    // 2. Validate the challenge (server signature + structure) and sign it.
    let signedXdr: string;
    try {
      WebAuth.readChallengeTx(
        challengeXdr,
        signingKey,
        this.config.stellarNetworkPassphrase,
        [domain],
        anchor.webAuthDomain,
      );

      const transaction = TransactionBuilder.fromXDR(
        challengeXdr,
        this.config.stellarNetworkPassphrase,
      );
      transaction.sign(Keypair.fromSecret(secretKey));
      signedXdr = transaction.toEnvelope().toXDR('base64').toString();
    } catch (err) {
      this.logger.warn(
        `SEP-10 challenge validation/signing failed for ${domain}: ${(err as Error).message}`,
      );
      throw new Sep10AuthError(
        domain,
        'challenge_parse',
        `Unable to validate or sign the SEP-10 challenge from anchor "${domain}": ${(err as Error).message}`,
      );
    }

    // 3. Exchange the signed challenge for a JWT.
    try {
      const tokenRes = await fetch(anchor.webAuthUrl, {
        method: 'POST',
        headers: this.sep10Headers(),
        body: new URLSearchParams({ transaction: signedXdr }).toString(),
      });
      if (!tokenRes.ok) {
        throw new Error(`anchor returned HTTP ${tokenRes.status}`);
      }
      const tokenPayload = (await tokenRes.json()) as { token?: string };
      if (!tokenPayload.token) {
        throw new Error('response did not include a token');
      }
      return tokenPayload.token;
    } catch (err) {
      this.logger.warn(
        `SEP-10 token exchange failed for ${domain}: ${(err as Error).message}`,
      );
      throw new Sep10AuthError(
        domain,
        'token_exchange',
        `Unable to exchange the signed SEP-10 challenge for a token with anchor "${domain}": ${(err as Error).message}`,
      );
    }
  }

  // ─── SEP-24: interactive initiation ───────────────────────────────────────

  /**
   * POST to the anchor's SEP-24 transfer server to start the interactive
   * flow. Returns the anchor-provided payload; the interactive URL comes
   * exclusively from the anchor's response.
   */
  private async initiateSep24(
    operation: Sep24Operation,
    domain: string,
    anchor: DiscoveredAnchor,
    assetCode: string,
    amount: number,
    userAccount: string,
    jwt: string,
  ): Promise<{ id?: string; type?: string; url: string }> {
    const endpoint = `${anchor.transferServerUrl.replace(/\/+$/, '')}/${operation}/interactive`;

    let payload: { id?: string; type?: string; url?: string };
    try {
      const body = new URLSearchParams({
        asset_code: assetCode,
        account: userAccount,
        lang: 'en',
      });
      if (amount > 0) {
        body.append('amount', String(amount));
      }

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: body.toString(),
      });
      if (!res.ok) {
        throw new Error(`anchor returned HTTP ${res.status}`);
      }
      payload = (await res.json()) as { id?: string; type?: string; url?: string };
    } catch (err) {
      this.logger.warn(
        `SEP-24 ${operation} initiation failed for ${domain}: ${(err as Error).message}`,
      );
      throw new Sep24InitiationError(
        domain,
        operation,
        `Unable to initiate a SEP-24 ${operation} with anchor "${domain}": ${(err as Error).message}`,
      );
    }

    if (!payload.url) {
      throw new Sep24InitiationError(
        domain,
        operation,
        `Anchor "${domain}" responded without an interactive url for ${operation}.`,
      );
    }

    return payload as { id?: string; type?: string; url: string };
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private sep10Headers(): Record<string, string> {
    return {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };
  }
}
