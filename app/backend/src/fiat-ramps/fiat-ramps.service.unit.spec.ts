import { HttpStatus } from '@nestjs/common';
import { Networks, Keypair, WebAuth, Transaction } from '@stellar/stellar-sdk';

import { FiatRampsService, AnchorIntegrationError, AnchorErrorCode } from './fiat-ramps.service';
import { TomlFetcherService } from '../asset-metadata/toml-fetcher.service';
import { AppConfigService } from '../config/app-config.service';

/**
 * Unit tests for the real SEP-10 + SEP-24 anchor handshake.
 *
 * The network boundary (global fetch) is stubbed to simulate a testnet anchor,
 * but all cryptography and transaction handling uses the genuine Stellar SDK:
 * challenge transactions are built with WebAuth.buildChallengeTx exactly like a
 * real anchor server would produce them.
 */

const ANCHOR_DOMAIN = 'anchor.example';
const WEB_AUTH_ENDPOINT = 'https://auth.anchor.example/auth';
const TRANSFER_SERVER = 'https://api.anchor.example';
const NETWORK_PASSPHRASE = Networks.TESTNET;

interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}

function jsonResponse(body: unknown, status = HttpStatus.OK): MockResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

describe('FiatRampsService (real SEP-24 handshake against stubbed anchor)', () => {
  let service: FiatRampsService;
  let tomlFetcher: { fetchStellarToml: jest.Mock };
  let config: AppConfigService;

  const clientKeypair = Keypair.random();
  const anchorServerKeypair = Keypair.random();
  const userKeypair = Keypair.random();

  let fetchMock: jest.Mock;

  /** stellar.toml advertising full SEP-24 + SEP-10 capabilities. */
  function anchorToml(overrides: Record<string, unknown> = {}) {
    return {
      SIGNING_KEY: anchorServerKeypair.publicKey(),
      WEB_AUTH_ENDPOINT,
      TRANSFER_SERVER_SEP0024: TRANSFER_SERVER,
      CURRENCIES: [
        { code: 'USDC', issuer: Keypair.random().publicKey() },
        { code: 'EURC', issuer: Keypair.random().publicKey() },
      ],
      ...overrides,
    };
  }

  /** A genuine SEP-10 challenge, signed by the anchor's server key. */
  function buildChallenge(signerKeypair = anchorServerKeypair): string {
    return WebAuth.buildChallengeTx(
      signerKeypair,
      clientKeypair.publicKey(),
      ANCHOR_DOMAIN,
      900,
      NETWORK_PASSPHRASE,
      'auth.anchor.example',
    );
  }

  /** Standard three-phase stubbed anchor: challenge -> token -> interactive URL. */
  function stubSuccessfulAnchor(sep24Response: Record<string, unknown>): void {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
      .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token' }))
      .mockResolvedValueOnce(jsonResponse(sep24Response));
  }

  async function expectAnchorError(
    promise: Promise<unknown>,
    code: AnchorErrorCode,
    status: HttpStatus,
  ): Promise<AnchorIntegrationError> {
    const error = (await promise.catch((e: unknown) => e)) as AnchorIntegrationError;
    expect(error).toBeInstanceOf(AnchorIntegrationError);
    expect(error.code).toBe(code);
    expect(error.getStatus()).toBe(status);
    expect(error.getResponse()).toMatchObject({
      type: 'anchor_integration_error',
      code,
    });
    return error;
  }

  beforeAll(() => {
    fetchMock = jest.fn();
    (global as Record<string, unknown>).fetch = fetchMock;
  });

  beforeEach(() => {
    fetchMock.mockReset();

    tomlFetcher = { fetchStellarToml: jest.fn() };
    config = {
      get stellarSecretKey() {
        return clientKeypair.secret();
      },
      get stellarNetworkPassphrase() {
        return NETWORK_PASSPHRASE;
      },
    } as unknown as AppConfigService;

    service = new FiatRampsService(tomlFetcher as unknown as TomlFetcherService, config);
  });

  describe('SEP-10 authentication + SEP-24 initiation', () => {
    it('performs the full deposit handshake and returns the anchor-negotiated interactive URL', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      stubSuccessfulAnchor({
        type: 'interactive_customer_info_needed',
        url: `${TRANSFER_SERVER}/sep24/deposit/abc123`,
        id: 'dep-tx-1',
      });

      const result = await service.initiateDeposit({
        assetCode: 'USDC',
        amount: 25.5,
        userAccount: userKeypair.publicKey(),
        anchorDomain: ANCHOR_DOMAIN,
      });

      // Discovery came from stellar.toml
      expect(tomlFetcher.fetchStellarToml).toHaveBeenCalledWith(ANCHOR_DOMAIN);

      // Phase 1: SEP-10 challenge requested for the configured account
      const [challengeUrl, challengeInit] = fetchMock.mock.calls[0];
      expect(challengeUrl).toBe(`${WEB_AUTH_ENDPOINT}?account=${clientKeypair.publicKey()}`);
      expect((challengeInit as RequestInit).method).toBe('GET');

      // Phase 2: signed challenge POSTed form-urlencoded per SEP-10
      const [authUrl, authInit] = fetchMock.mock.calls[1] as [string, RequestInit];
      expect(authUrl).toBe(WEB_AUTH_ENDPOINT);
      expect(new Headers(authInit.headers).get('Content-Type')).toBe('application/x-www-form-urlencoded');
      const submittedTx = new URLSearchParams(authInit.body as string).get('transaction');
      expect(submittedTx).toBeTruthy();
      // The submitted transaction must be a valid, client-signed challenge
      expect(() => new Transaction(submittedTx as string, NETWORK_PASSPHRASE)).not.toThrow();

      // Phase 3: SEP-24 initiation carries the JWT and is form-urlencoded
      const [depositUrl, depositInit] = fetchMock.mock.calls[2] as [string, RequestInit];
      expect(depositUrl).toBe(`${TRANSFER_SERVER}/transactions/deposit/interactive`);
      expect(new Headers(depositInit.headers).get('Authorization')).toBe('Bearer jwt-token');
      expect(new Headers(depositInit.headers).get('Content-Type')).toBe('application/x-www-form-urlencoded');
      const params = new URLSearchParams(depositInit.body as string);
      expect(params.get('asset_code')).toBe('USDC');
      expect(params.get('account')).toBe(userKeypair.publicKey());
      expect(params.get('amount')).toBe('25.5');

      // Interactive URL comes from the anchor response, not string construction
      expect(result).toEqual({
        status: 'success',
        transaction_id: 'dep-tx-1',
        type: 'interactive_customer_info_needed',
        url: `${TRANSFER_SERVER}/sep24/deposit/abc123`,
      });
    });

    it('performs the full withdrawal handshake', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      stubSuccessfulAnchor({
        type: 'interactive_customer_info_needed',
        url: `${TRANSFER_SERVER}/sep24/withdraw/xyz789`,
        id: 'wth-tx-1',
      });

      const result = await service.initiateWithdrawal({
        assetCode: 'USDC',
        amount: 5,
        userAccount: userKeypair.publicKey(),
        anchorDomain: ANCHOR_DOMAIN,
      });

      const [withdrawUrl, withdrawInit] = fetchMock.mock.calls[2] as [string, RequestInit];
      expect(withdrawUrl).toBe(`${TRANSFER_SERVER}/transactions/withdraw/interactive`);
      expect(new Headers(withdrawInit.headers).get('Authorization')).toBe('Bearer jwt-token');
      expect(result.url).toBe(`${TRANSFER_SERVER}/sep24/withdraw/xyz789`);
      expect(result.transaction_id).toBe('wth-tx-1');
    });

    it('falls back to TRANSFER_SERVER when SEP-0024 transfer server is not advertised separately', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(
        anchorToml({ TRANSFER_SERVER_SEP0024: undefined, TRANSFER_SERVER: 'https://legacy.anchor.example' }),
      );
      stubSuccessfulAnchor({ url: 'https://legacy.anchor.example/interactive' });

      const result = await service.initiateDeposit({
        assetCode: 'USDC',
        amount: 1,
        userAccount: userKeypair.publicKey(),
        anchorDomain: ANCHOR_DOMAIN,
      });

      expect(fetchMock.mock.calls[2][0]).toBe('https://legacy.anchor.example/transactions/deposit/interactive');
      expect(result.url).toBe('https://legacy.anchor.example/interactive');
    });

    it('defaults the SEP-24 account parameter to the authenticated account when userAccount is omitted', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      stubSuccessfulAnchor({ url: `${TRANSFER_SERVER}/sep24/deposit/self` });

      await service.initiateDeposit({ assetCode: 'USDC', amount: 1, anchorDomain: ANCHOR_DOMAIN });

      const [, init] = fetchMock.mock.calls[2] as [string, RequestInit];
      expect(new URLSearchParams(init.body as string).get('account')).toBe(clientKeypair.publicKey());
    });
  });

  describe('anchor discovery errors', () => {
    it('throws a typed error when stellar.toml cannot be fetched', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(null);

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 1, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.ANCHOR_UNREACHABLE,
        HttpStatus.BAD_GATEWAY,
      );
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('throws a typed error when the toml does not advertise SEP-24/SEP-10 endpoints', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml({ WEB_AUTH_ENDPOINT: undefined }));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 1, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.ANCHOR_UNREACHABLE,
        HttpStatus.BAD_GATEWAY,
      );
    });
  });

  describe('unsupported assets', () => {
    it('rejects assets missing from the anchor CURRENCIES list', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'SCAM', amount: 1, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.ASSET_UNSUPPORTED,
        HttpStatus.BAD_REQUEST,
      );
      // No handshake traffic should occur for an unsupported asset
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('rejects when the anchor advertises no currencies at all', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml({ CURRENCIES: undefined }));

      await expectAnchorError(
        service.initiateWithdrawal({ assetCode: 'USDC', amount: 1, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.ASSET_UNSUPPORTED,
        HttpStatus.BAD_REQUEST,
      );
    });
  });

  describe('SEP-10 authentication failures', () => {
    it('throws AUTH_FAILED when the anchor rejects the signed challenge', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
        .mockResolvedValueOnce(jsonResponse({ error: 'invalid signature' }, HttpStatus.UNAUTHORIZED));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.AUTH_FAILED,
        HttpStatus.UNAUTHORIZED,
      );
    });

    it('throws AUTH_FAILED when no auth endpoint responds OK for the challenge request', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'boom' }, HttpStatus.SERVICE_UNAVAILABLE));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.ANCHOR_UNREACHABLE,
        HttpStatus.BAD_GATEWAY,
      );
    });

    it('throws AUTH_FAILED when the anchor omits the token from the auth response', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
        .mockResolvedValueOnce(jsonResponse({ unexpected: true }));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.AUTH_FAILED,
        HttpStatus.BAD_GATEWAY,
      );
    });

    it('throws CHALLENGE_INVALID for a malformed challenge payload', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock.mockResolvedValueOnce(jsonResponse({ transaction: 'definitely-not-a-transaction' }));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.CHALLENGE_INVALID,
        HttpStatus.BAD_GATEWAY,
      );
    });

    it('throws CHALLENGE_INVALID when the challenge was not signed by the advertised SIGNING_KEY', async () => {
      const impostorKeypair = Keypair.random();
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml()); // advertises legit SIGNING_KEY
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge(impostorKeypair) }))
        // Auth never reached, but provide a fallback in case of regressions
        .mockResolvedValue(jsonResponse({ token: 'should-not-be-used' }));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.CHALLENGE_INVALID,
        HttpStatus.BAD_GATEWAY,
      );
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('throws AUTH_NOT_CONFIGURED when STELLAR_SECRET_KEY is missing', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      config = {
        get stellarSecretKey() {
          return undefined;
        },
        get stellarNetworkPassphrase() {
          return NETWORK_PASSPHRASE;
        },
      } as unknown as AppConfigService;
      service = new FiatRampsService(tomlFetcher as unknown as TomlFetcherService, config);

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.AUTH_NOT_CONFIGURED,
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    });
  });

  describe('SEP-24 initiation failures', () => {
    it('throws INTERACTIVE_FLOW_FAILED when the anchor rejects the initiation', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token' }))
        .mockResolvedValueOnce(jsonResponse({ error: 'asset not supported for region' }, HttpStatus.BAD_REQUEST));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.INTERACTIVE_FLOW_FAILED,
        HttpStatus.BAD_GATEWAY,
      );
    });

    it('throws INTERACTIVE_FLOW_FAILED when the anchor response has no interactive URL', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token' }))
        .mockResolvedValueOnce(jsonResponse({ id: 'tx-without-url' }));

      await expectAnchorError(
        service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.INTERACTIVE_FLOW_FAILED,
        HttpStatus.BAD_GATEWAY,
      );
    });

    it('converts network-level failures into a typed ANCHOR_UNREACHABLE error instead of a generic 500', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token' }))
        .mockRejectedValueOnce(new TypeError('fetch failed'));

      await expectAnchorError(
        service.initiateWithdrawal({ assetCode: 'USDC', amount: 5, userAccount: userKeypair.publicKey(), anchorDomain: ANCHOR_DOMAIN }),
        AnchorErrorCode.ANCHOR_UNREACHABLE,
        HttpStatus.BAD_GATEWAY,
      );
    });

    it('accepts alternate interactive URL field names (redirect_url)', async () => {
      tomlFetcher.fetchStellarToml.mockResolvedValue(anchorToml());
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ transaction: buildChallenge() }))
        .mockResolvedValueOnce(jsonResponse({ access_token: 'jwt-alt-token' }))
        .mockResolvedValueOnce(jsonResponse({ redirect_url: 'https://kyc.anchor.example/start', transaction: { id: 'nested-id' } }));

      const result = await service.initiateDeposit({
        assetCode: 'USDC',
        amount: 5,
        userAccount: userKeypair.publicKey(),
        anchorDomain: ANCHOR_DOMAIN,
      });

      expect(result.url).toBe('https://kyc.anchor.example/start');
      expect(result.transaction_id).toBe('nested-id');
      // access_token is accepted as an alternative token field name
      expect(new Headers(fetchMock.mock.calls[2][1].headers).get('Authorization')).toBe('Bearer jwt-alt-token');
    });
  });
});
