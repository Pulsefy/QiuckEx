import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import * as StellarSdk from '@stellar/stellar-sdk';
import { TomlFetcherService } from '../asset-metadata/toml-fetcher.service';
import { AppConfigService } from '../config/app-config.service';

export class AnchorIntegrationError extends HttpException {
  constructor(message: string, status = HttpStatus.BAD_GATEWAY) {
    super({ type: 'anchor_integration_error', message }, status);
  }
}

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

  private async discoverAnchor(anchorDomain: string) {
    const toml = await this.tomlFetcher.fetchStellarToml(anchorDomain);
    if (!toml) {
      throw new AnchorIntegrationError(`Unable to fetch stellar.toml for ${anchorDomain}`, HttpStatus.BAD_GATEWAY);
    }

    const transferServer = (toml as any).TRANSFER_SERVER_SEP0024 || (toml as any).TRANSFER_SERVER;
    const webAuth = (toml as any).WEB_AUTH_ENDPOINT || (toml as any).WEB_AUTH;

    if (!transferServer || !webAuth) {
      throw new AnchorIntegrationError(`Anchor ${anchorDomain} does not advertise SEP-24/SEP-10 endpoints`, HttpStatus.BAD_GATEWAY);
    }

    return { toml, transferServer, webAuth };
  }

  private async performSep10Auth(webAuthEndpoint: string, userAccount: string): Promise<string> {
    const secret = this.config.stellarSecretKey;
    if (!secret) {
      throw new AnchorIntegrationError('Server not configured with STELLAR_SECRET_KEY for SEP-10 auth', HttpStatus.SERVICE_UNAVAILABLE);
    }

    // 1) Request challenge transaction
    const challengeUrl = `${webAuthEndpoint.replace(/\/$/, '')}?account=${encodeURIComponent(userAccount)}`;
    this.logger.debug(`Requesting SEP-10 challenge from ${challengeUrl}`);

    const challengeRes = await fetch(challengeUrl, { method: 'GET', headers: { Accept: 'application/json' } });
    if (!challengeRes.ok) {
      throw new AnchorIntegrationError(`Failed to fetch SEP-10 challenge from ${webAuthEndpoint}`, HttpStatus.BAD_GATEWAY);
    }

    const challengeJson = await challengeRes.json().catch(() => ({}));
    const challengeTx = challengeJson.transaction || challengeJson.challenge || challengeJson.transaction_xdr || challengeJson.tx;
    if (!challengeTx || typeof challengeTx !== 'string') {
      throw new AnchorIntegrationError('Invalid SEP-10 challenge received from anchor', HttpStatus.BAD_GATEWAY);
    }

    // 2) Sign challenge transaction using server secret
    let signedTxBase64: string;
    try {
      const tx = new StellarSdk.Transaction(challengeTx, this.config.stellarNetworkPassphrase);
      const kp = StellarSdk.Keypair.fromSecret(secret);
      tx.sign(kp);
      signedTxBase64 = tx.toEnvelope().toXDR('base64');
    } catch (err) {
      this.logger.error(`Failed to sign SEP-10 challenge: ${err.message}`);
      throw new AnchorIntegrationError('Failed to sign SEP-10 challenge', HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // 3) Submit signed challenge to get JWT
    const authRes = await fetch(webAuthEndpoint.replace(/\/$/, ''), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ transaction: signedTxBase64 }),
    });

    if (!authRes.ok) {
      const text = await authRes.text().catch(() => '');
      this.logger.warn(`SEP-10 auth failed: ${authRes.status} ${text}`);
      throw new AnchorIntegrationError('SEP-10 authentication failed with anchor', HttpStatus.UNAUTHORIZED);
    }

    const authJson = await authRes.json().catch(() => ({}));
    const token = authJson.token || authJson.access_token || authJson.jwt;
    if (!token) {
      throw new AnchorIntegrationError('Anchor did not return an auth token after SEP-10', HttpStatus.BAD_GATEWAY);
    }

    return token;
  }

  async initiateDeposit(depositDto: { assetCode: string; amount: number; userAccount: string; anchorDomain: string }) {
    this.logger.log(`Initiating SEP-24 deposit flow with ${depositDto.anchorDomain}`);
    try {
      const { toml, transferServer, webAuth } = await this.discoverAnchor(depositDto.anchorDomain);

      // Validate asset is supported per stellar.toml currencies
      const currencyList = (toml as any).CURRENCIES || [];
      const found = Array.isArray(currencyList) && currencyList.find((c: any) => String(c.code).toUpperCase() === String(depositDto.assetCode).toUpperCase());
      if (!found) {
        throw new AnchorIntegrationError(`Anchor ${depositDto.anchorDomain} does not support asset ${depositDto.assetCode}`, HttpStatus.BAD_REQUEST);
      }

      // Perform SEP-10 and get token
      const token = await this.performSep10Auth(webAuth, depositDto.userAccount);

      // Initiate SEP-24 interactive deposit
      const depositUrl = `${transferServer.replace(/\/$/, '')}/transactions/deposit/interactive`;
      const body = {
        asset_code: depositDto.assetCode,
        account: depositDto.userAccount,
        amount: depositDto.amount?.toString?.() ?? undefined,
      };

      const res = await fetch(depositUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const txt = await res.text().catch(() => '');
        this.logger.warn(`SEP-24 deposit initiation failed: ${res.status} ${txt}`);
        throw new AnchorIntegrationError('Failed to initiate SEP-24 deposit with anchor', HttpStatus.BAD_GATEWAY);
      }

      const json = await res.json().catch(() => ({}));
      return {
        status: 'success',
        transaction_id: `dep_${Date.now()}`,
        type: json.type || json.status || 'interactive_customer_info_needed',
        url: json.url || json.redirect_url || json.client_redirect_url,
      };
    } catch (error) {
      if (error instanceof AnchorIntegrationError) throw error;
      this.logger.error(`Error initiating deposit: ${error?.message ?? String(error)}`);
      throw new HttpException('Failed to initiate deposit', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async initiateWithdrawal(withdrawalDto: { assetCode: string; amount: number; userAccount: string; anchorDomain: string }) {
    this.logger.log(`Initiating SEP-24 withdrawal flow with ${withdrawalDto.anchorDomain}`);
    try {
      const { toml, transferServer, webAuth } = await this.discoverAnchor(withdrawalDto.anchorDomain);

      const currencyList = (toml as any).CURRENCIES || [];
      const found = Array.isArray(currencyList) && currencyList.find((c: any) => String(c.code).toUpperCase() === String(withdrawalDto.assetCode).toUpperCase());
      if (!found) {
        throw new AnchorIntegrationError(`Anchor ${withdrawalDto.anchorDomain} does not support asset ${withdrawalDto.assetCode}`, HttpStatus.BAD_REQUEST);
      }

      const token = await this.performSep10Auth(webAuth, withdrawalDto.userAccount);

      const withdrawUrl = `${transferServer.replace(/\/$/, '')}/transactions/withdraw/interactive`;
      const body = {
        asset_code: withdrawalDto.assetCode,
        account: withdrawalDto.userAccount,
        amount: withdrawalDto.amount?.toString?.() ?? undefined,
      };

      const res = await fetch(withdrawUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const txt = await res.text().catch(() => '');
        this.logger.warn(`SEP-24 withdrawal initiation failed: ${res.status} ${txt}`);
        throw new AnchorIntegrationError('Failed to initiate SEP-24 withdrawal with anchor', HttpStatus.BAD_GATEWAY);
      }

      const json = await res.json().catch(() => ({}));
      return {
        status: 'success',
        transaction_id: `wth_${Date.now()}`,
        type: json.type || json.status || 'interactive_customer_info_needed',
        url: json.url || json.redirect_url || json.client_redirect_url,
      };
    } catch (error) {
      if (error instanceof AnchorIntegrationError) throw error;
      this.logger.error(`Error initiating withdrawal: ${error?.message ?? String(error)}`);
      throw new HttpException('Failed to initiate withdrawal', HttpStatus.INTERNAL_SERVER_ERROR);
    }
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
