import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import * as StellarSdk from '@stellar/stellar-sdk';
import { TomlFetcherService } from '../asset-metadata/toml-fetcher.service';
import { AppConfigService } from '../config/app-config.service';

/**
 * Stable machine-readable error codes for anchor integration failures.
 * These are part of the public API contract and must not be renamed.
 */
export enum AnchorErrorCode {
  /** Anchor domain could not be resolved, was unreachable, or returned a malformed response. */
  ANCHOR_UNREACHABLE = 'ANCHOR_UNREACHABLE',
  /** The requested asset is not advertised in the anchor's stellar.toml CURRENCIES. */
  ASSET_UNSUPPORTED = 'ASSET_UNSUPPORTED',
  /** STELLAR_SECRET_KEY is not configured on the server; SEP-10 cannot be performed. */
  AUTH_NOT_CONFIGURED = 'AUTH_NOT_CONFIGURED',
  /** SEP-10 authentication failed (rejected by the anchor or token missing). */
  AUTH_FAILED = 'AUTH_FAILED',
  /** The SEP-10 challenge transaction is missing, malformed, or fails validation. */
  CHALLENGE_INVALID = 'CHALLENGE_INVALID',
  /** SEP-24 interactive flow could not be initiated. */
  INTERACTIVE_FLOW_FAILED = 'INTERACTIVE_FLOW_FAILED',
}

/**
 * Typed error thrown for every failure of the SEP-24 anchor integration.
 * The HTTP response body always has the shape:
 *   { type: 'anchor_integration_error', code: AnchorErrorCode, message: string }
 */
export class AnchorIntegrationError extends HttpException {
  readonly code: AnchorErrorCode;

  constructor(message: string, status = HttpStatus.BAD_GATEWAY, code = AnchorErrorCode.ANCHOR_UNREACHABLE) {
    super({ type: 'anchor_integration_error', code, message }, status);
    this.code = code;
  }
}

export interface Sep24FlowRequestDto {
  assetCode: string;
  amount?: number;
  userAccount?: string;
  anchorDomain: string;
  memo?: string;
  memoType?: string;
  lang?: string;
}

export interface Sep24FlowResponse {
  status: 'success';
  transaction_id: string;
  type: string;
  url: string;
}

interface DiscoveredAnchor {
  toml: Record<string, unknown>;
  transferServer: string;
  webAuthEndpoint: string;
  signingKey?: string;
}

const HTTP_TIMEOUT_MS = 5000;

@Injectable()
export class FiatRampsService {
  private readonly logger = new Logger(FiatRampsService.name);

  constructor(
    private readonly tomlFetcher: TomlFetcherService,
    private readonly config: AppConfigService,
  ) {}

  async getAvailableAnchors(assetCode: string, country: string) {
    this.logger.log(`Fetching available anchors for ${assetCode} in ${country}`);
    // Keep existing mock for anchor discovery UI; real discovery is handled per-anchor during initiation
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
        }
      ]
    };
  }

  /**
   * Discover the anchor's capabilities from its stellar.toml (SEP-1).
   * Endpoints are never assumed or constructed from the domain alone.
   */
  private async discoverAnchor(anchorDomain: string): Promise<DiscoveredAnchor> {
    const toml = await this.tomlFetcher.fetchStellarToml(anchorDomain);
    if (!toml) {
      throw new AnchorIntegrationError(
        `Unable to fetch stellar.toml for ${anchorDomain}`,
        HttpStatus.BAD_GATEWAY,
        AnchorErrorCode.ANCHOR_UNREACHABLE,
      );
    }

    const record = toml as Record<string, unknown>;
    const transferServer = (record.TRANSFER_SERVER_SEP0024 || record.TRANSFER_SERVER) as string | undefined;
    const webAuthEndpoint = record.WEB_AUTH_ENDPOINT as string | undefined;
    const signingKey = record.SIGNING_KEY as string | undefined;

    if (!transferServer || !webAuthEndpoint) {
      throw new AnchorIntegrationError(
        `Anchor ${anchorDomain} does not advertise SEP-24/SEP-10 endpoints`,
        HttpStatus.BAD_GATEWAY,
        AnchorErrorCode.ANCHOR_UNREACHABLE,
      );
    }

    return { toml: record, transferServer, webAuthEndpoint, signingKey };
  }

  /**
   * Confirm the requested asset is advertised by the anchor in stellar.toml.
   */
  private assertAssetSupported(anchor: DiscoveredAnchor, anchorDomain: string, assetCode: string): void {
    const currencyList = anchor.toml.CURRENCIES;
    const supported =
      Array.isArray(currencyList) &&
      currencyList.some(
        (c: { code?: string }) => typeof c?.code === 'string' && c.code.toUpperCase() === assetCode.toUpperCase(),
      );
    if (!supported) {
      throw new AnchorIntegrationError(
        `Anchor ${anchorDomain} does not support asset ${assetCode}`,
        HttpStatus.BAD_REQUEST,
        AnchorErrorCode.ASSET_UNSUPPORTED,
      );
    }
  }

  /**
   * fetch() wrapper that converts network failures / timeouts into a stable
   * typed error instead of an unhandled TypeError.
   */
  private async anchorFetch(url: string, init: RequestInit): Promise<Response> {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
    } catch (error) {
      this.logger.warn(`Anchor request failed (${url}): ${error?.message ?? String(error)}`);
      throw new AnchorIntegrationError(
        `Anchor endpoint unreachable: ${url}`,
        HttpStatus.BAD_GATEWAY,
        AnchorErrorCode.ANCHOR_UNREACHABLE,
      );
    }
  }

  /**
   * Perform full SEP-10 authentication against the anchor:
   *   1. GET the challenge transaction for the configured server account.
   *   2. Validate the challenge (against the anchor SIGNING_KEY when advertised).
   *   3. Client-sign it with the configured STELLAR_SECRET_KEY.
   *   4. POST the signed challenge (form-urlencoded per SEP-10) and extract the JWT.
   * The resulting token is required for all subsequent SEP-24 requests.
   */
  private async performSep10Auth(anchor: DiscoveredAnchor, anchorDomain: string): Promise<{ token: string; clientAccount: string }> {
    const secret = this.config.stellarSecretKey;
    if (!secret) {
      throw new AnchorIntegrationError(
        'Server not configured with STELLAR_SECRET_KEY for SEP-10 auth',
        HttpStatus.SERVICE_UNAVAILABLE,
        AnchorErrorCode.AUTH_NOT_CONFIGURED,
      );
    }

    const clientKeypair = StellarSdk.Keypair.fromSecret(secret);
    const clientAccount = clientKeypair.publicKey();
    const networkPassphrase = this.config.stellarNetworkPassphrase;

    // 1) Request challenge transaction
    const webAuthUrl = new URL(anchor.webAuthEndpoint);
    webAuthUrl.searchParams.set('account', clientAccount);
    this.logger.debug(`Requesting SEP-10 challenge from ${webAuthUrl.toString()}`);

    const challengeRes = await this.anchorFetch(webAuthUrl.toString(), {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!challengeRes.ok) {
      throw new AnchorIntegrationError(
        `Failed to fetch SEP-10 challenge from ${anchor.webAuthEndpoint}`,
        HttpStatus.BAD_GATEWAY,
        AnchorErrorCode.ANCHOR_UNREACHABLE,
      );
    }

    const challengeJson = (await challengeRes.json().catch(() => ({}))) as Record<string, unknown>;
    const challengeTx = challengeJson.transaction ?? challengeJson.transaction_xdr;
    if (!challengeTx || typeof challengeTx !== 'string') {
      throw new AnchorIntegrationError(
        'Invalid SEP-10 challenge received from anchor',
        HttpStatus.BAD_GATEWAY,
        AnchorErrorCode.CHALLENGE_INVALID,
      );
    }

    // 2) Validate the challenge before signing anything.
    if (anchor.signingKey) {
      try {
        StellarSdk.WebAuth.readChallengeTx(
          challengeTx,
          anchor.signingKey,
          networkPassphrase,
          anchorDomain,
          webAuthUrl.hostname,
        );
      } catch (error) {
        this.logger.warn(`SEP-10 challenge failed validation: ${error?.message ?? String(error)}`);
        throw new AnchorIntegrationError(
          'SEP-10 challenge failed validation against anchor signing key',
          HttpStatus.BAD_GATEWAY,
          AnchorErrorCode.CHALLENGE_INVALID,
        );
      }
    } else {
      // Without SIGNING_KEY we cannot verify provenance; at minimum ensure it parses.
      try {
        new StellarSdk.Transaction(challengeTx, networkPassphrase);
      } catch (error) {
        this.logger.warn(`SEP-10 challenge is malformed: ${error?.message ?? String(error)}`);
        throw new AnchorIntegrationError(
          'Invalid SEP-10 challenge received from anchor',
          HttpStatus.BAD_GATEWAY,
          AnchorErrorCode.CHALLENGE_INVALID,
        );
      }
    }

    // 3) Sign the challenge as the client account
    let signedTxBase64: string;
    try {
      const tx = new StellarSdk.Transaction(challengeTx, networkPassphrase);
      tx.sign(clientKeypair);
      signedTxBase64 = tx.toEnvelope().toXDR('base64');
    } catch (error) {
      this.logger.error(`Failed to sign SEP-10 challenge: ${error?.message ?? String(error)}`);
      throw new AnchorIntegrationError(
        'Failed to sign SEP-10 challenge',
        HttpStatus.INTERNAL_SERVER_ERROR,
        AnchorErrorCode.CHALLENGE_INVALID,
      );
    }

    // 4) Submit signed challenge (application/x-www-form-urlencoded per SEP-10)
    const authRes = await this.anchorFetch(anchor.webAuthEndpoint.replace(/\/$/, ''), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ transaction: signedTxBase64 }).toString(),
    });

    if (!authRes.ok) {
      const text = await authRes.text().catch(() => '');
      this.logger.warn(`SEP-10 auth failed: ${authRes.status} ${text}`);
      throw new AnchorIntegrationError(
        'SEP-10 authentication failed with anchor',
        HttpStatus.UNAUTHORIZED,
        AnchorErrorCode.AUTH_FAILED,
      );
    }

    const authJson = (await authRes.json().catch(() => ({}))) as Record<string, unknown>;
    const token = (authJson.token || authJson.access_token || authJson.jwt) as string | undefined;
    if (!token) {
      throw new AnchorIntegrationError(
        'Anchor did not return an auth token after SEP-10',
        HttpStatus.BAD_GATEWAY,
        AnchorErrorCode.AUTH_FAILED,
      );
    }

    return { token, clientAccount };
  }

  /**
   * Shared SEP-24 initiation logic. Interactive URLs always come from the
   * anchor's response — they are never constructed locally.
   */
  private async initiateInteractiveFlow(
    kind: 'deposit' | 'withdraw',
    dto: Sep24FlowRequestDto,
  ): Promise<Sep24FlowResponse> {
    const kindLabel = kind === 'deposit' ? 'deposit' : 'withdrawal';
    this.logger.log(`Initiating SEP-24 ${kindLabel} flow with ${dto.anchorDomain}`);
    try {
      const anchor = await this.discoverAnchor(dto.anchorDomain);
      this.assertAssetSupported(anchor, dto.anchorDomain, dto.assetCode);
      const { token, clientAccount } = await this.performSep10Auth(anchor, dto.anchorDomain);

      const interactiveUrl = `${anchor.transferServer.replace(/\/$/, '')}/transactions/${kind}/interactive`;
      const params: Record<string, string> = {
        asset_code: dto.assetCode,
        account: dto.userAccount || clientAccount,
      };
      if (dto.amount != null) params.amount = String(dto.amount);
      if (dto.memo) params.memo = dto.memo;
      if (dto.memoType) params.memo_type = dto.memoType;
      if (dto.lang) params.lang = dto.lang;

      const res = await this.anchorFetch(interactiveUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
        },
        body: new URLSearchParams(params).toString(),
      });

      if (!res.ok) {
        const txt = await res.text().catch(() => '');
        this.logger.warn(`SEP-24 ${kindLabel} initiation failed: ${res.status} ${txt}`);
        throw new AnchorIntegrationError(
          `Failed to initiate SEP-24 ${kindLabel} with anchor`,
          HttpStatus.BAD_GATEWAY,
          AnchorErrorCode.INTERACTIVE_FLOW_FAILED,
        );
      }

      const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      const nestedTransaction = json.transaction as Record<string, unknown> | undefined;
      const url = (json.url || json.redirect_url || json.client_redirect_url) as string | undefined;
      if (!url) {
        throw new AnchorIntegrationError(
          `Anchor did not return an interactive URL for SEP-24 ${kindLabel}`,
          HttpStatus.BAD_GATEWAY,
          AnchorErrorCode.INTERACTIVE_FLOW_FAILED,
        );
      }

      const transactionId =
        json.id || json.transaction_id || nestedTransaction?.id || `${kind.slice(0, 3)}_${Date.now()}`;
      const type = json.type || json.status || 'interactive_customer_info_needed';

      return {
        status: 'success',
        transaction_id: String(transactionId),
        type: String(type),
        url: String(url),
      };
    } catch (error) {
      if (error instanceof AnchorIntegrationError) throw error;
      this.logger.error(`Unexpected error during SEP-24 ${kindLabel}: ${error?.message ?? String(error)}`);
      throw new AnchorIntegrationError(
        `Failed to initiate ${kindLabel}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
        AnchorErrorCode.INTERACTIVE_FLOW_FAILED,
      );
    }
  }

  initiateDeposit(depositDto: Sep24FlowRequestDto): Promise<Sep24FlowResponse> {
    return this.initiateInteractiveFlow('deposit', depositDto);
  }

  initiateWithdrawal(withdrawalDto: Sep24FlowRequestDto): Promise<Sep24FlowResponse> {
    return this.initiateInteractiveFlow('withdraw', withdrawalDto);
  }

  async handleKycCallback(callbackData: unknown) {
    this.logger.log(`Received KYC callback update: ${JSON.stringify(callbackData)}`);
    return { status: 'acknowledged' };
  }

  async updateTransactionStatus(statusData: unknown) {
    this.logger.log(`Received transaction status update: ${JSON.stringify(statusData)}`);
    return { status: 'acknowledged' };
  }
}
