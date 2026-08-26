import { Test, TestingModule } from '@nestjs/testing';
import {
  Keypair,
  Networks,
  StellarToml,
  WebAuth,
} from '@stellar/stellar-sdk';

import { AppConfigService } from '../config/app-config.service';
import { FiatRampsService } from './fiat-ramps.service';
import {
  AnchorNotFoundError,
  FiatRampsConfigurationError,
  Sep10AuthError,
  Sep24InitiationError,
  UnsupportedAssetError,
} from './errors';

const NETWORK_PASSPHRASE = Networks.TESTNET;
const ANCHOR_DOMAIN = 'anchor.example';
const AUTH_URL = `https://${ANCHOR_DOMAIN}/auth`;
const TRANSFER_URL = `https://${ANCHOR_DOMAIN}/sep24`;

/** Stub anchor signing keypair (SIGNING_KEY in stellar.toml). */
const serverKeypair = Keypair.random();
/** Backend wallet keypair (STELLAR_SECRET_KEY / STELLAR_PUBLIC_KEY). */
const clientKeypair = Keypair.random();

const mockAppConfig = {
  stellarSecretKey: clientKeypair.secret(),
  stellarPublicKey: clientKeypair.publicKey(),
  stellarNetworkPassphrase: NETWORK_PASSPHRASE,
};

const minimalAppConfig = {
  stellarSecretKey: undefined,
  stellarPublicKey: undefined,
  stellarNetworkPassphrase: NETWORK_PASSPHRASE,
};

function buildChallenge(account: string): string {
  return WebAuth.buildChallengeTx(
    serverKeypair,
    account,
    ANCHOR_DOMAIN,
    300,
    NETWORK_PASSPHRASE,
    ANCHOR_DOMAIN,
  );
}

function anchorToml(
  overrides: Partial<StellarToml.Api.StellarToml> = {},
): StellarToml.Api.StellarToml {
  return {
    WEB_AUTH_ENDPOINT: AUTH_URL,
    TRANSFER_SERVER_SEP0024: TRANSFER_URL,
    WEB_AUTH_DOMAIN: ANCHOR_DOMAIN,
    SIGNING_KEY: serverKeypair.publicKey(),
    CURRENCIES: [
      { code: 'USDC', issuer: serverKeypair.publicKey() },
      { code: 'XLM' },
    ],
    ...overrides,
  };
}

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return { ok, status, json: async () => body } as unknown as Response;
}

describe('FiatRampsService', () => {
  let service: FiatRampsService;
  let resolveSpy: jest.SpyInstance;
  let fetchSpy: jest.SpyInstance;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FiatRampsService,
        { provide: AppConfigService, useValue: mockAppConfig },
      ],
    }).compile();

    service = module.get<FiatRampsService>(FiatRampsService);
    resolveSpy = jest.spyOn(StellarToml.Resolver, 'resolve');
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('initiateDeposit', () => {
    it('completes the full SEP-01/SEP-10/SEP-24 handshake and returns the anchor-provided URL', async () => {
      const challenge = buildChallenge(clientKeypair.publicKey());
      const interactiveUrl = `${TRANSFER_URL}/deposit?token=abc123`;

      resolveSpy.mockResolvedValue(anchorToml());
      fetchSpy
        .mockResolvedValueOnce(jsonResponse({ transaction: challenge }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token-123' }))
        .mockResolvedValueOnce(
          jsonResponse({
            id: 'dep-123',
            type: 'interactive_customer_info_needed',
            url: interactiveUrl,
          }),
        );

      const result = await service.initiateDeposit({
        assetCode: 'USDC',
        amount: 100,
        userAccount: 'GUSER123',
        anchorDomain: ANCHOR_DOMAIN,
      });

      expect(result).toEqual({
        status: 'success',
        transaction_id: 'dep-123',
        type: 'interactive_customer_info_needed',
        url: interactiveUrl,
      });

      // SEP-01: resolved the anchor's stellar.toml for the requested domain.
      expect(resolveSpy).toHaveBeenCalledWith(
        ANCHOR_DOMAIN,
        expect.objectContaining({ allowHttp: false }),
      );

      // SEP-10 step 1: challenge requested for the backend public key.
      const challengeCall = fetchSpy.mock.calls[0];
      expect(challengeCall[0]).toBe(AUTH_URL);
      const challengeBody = new URLSearchParams(
        (challengeCall[1] as RequestInit).body as string,
      );
      expect(challengeBody.get('account')).toBe(clientKeypair.publicKey());

      // SEP-10 step 2: the submitted transaction is the challenge signed by
      // the backend keypair (real signature verification).
      const tokenCall = fetchSpy.mock.calls[1];
      const tokenBody = new URLSearchParams(
        (tokenCall[1] as RequestInit).body as string,
      );
      const signedXdr = tokenBody.get('transaction') as string;
      const signers = WebAuth.verifyChallengeTxSigners(
        signedXdr,
        serverKeypair.publicKey(),
        NETWORK_PASSPHRASE,
        [clientKeypair.publicKey()],
        [ANCHOR_DOMAIN],
        ANCHOR_DOMAIN,
      );
      expect(signers).toContain(clientKeypair.publicKey());

      // SEP-24: authenticated POST to /deposit/interactive with the JWT.
      const sep24Call = fetchSpy.mock.calls[2];
      expect(sep24Call[0]).toBe(`${TRANSFER_URL}/deposit/interactive`);
      const sep24Init = sep24Call[1] as RequestInit;
      expect((sep24Init.headers as Record<string, string>).Authorization).toBe(
        'Bearer jwt-token-123',
      );
      const sep24Body = new URLSearchParams(sep24Init.body as string);
      expect(sep24Body.get('asset_code')).toBe('USDC');
      expect(sep24Body.get('account')).toBe('GUSER123');
    });

    it('throws AnchorNotFoundError when stellar.toml cannot be resolved', async () => {
      resolveSpy.mockRejectedValue(new Error('connection refused'));

      await expect(
        service.initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        }),
      ).rejects.toThrow(AnchorNotFoundError);

      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('throws AnchorNotFoundError when required endpoints are missing from stellar.toml', async () => {
      resolveSpy.mockResolvedValue(
        anchorToml({ TRANSFER_SERVER_SEP0024: undefined }),
      );

      await expect(
        service.initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        }),
      ).rejects.toThrow(AnchorNotFoundError);
    });

    it('throws UnsupportedAssetError when the asset is not listed by the anchor', async () => {
      resolveSpy.mockResolvedValue(anchorToml());

      const err = await service
        .initiateDeposit({
          assetCode: 'EURC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(UnsupportedAssetError);
      expect((err as UnsupportedAssetError).assetCode).toBe('EURC');
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('throws Sep10AuthError with phase token_exchange when the anchor rejects the token exchange', async () => {
      const challenge = buildChallenge(clientKeypair.publicKey());
      resolveSpy.mockResolvedValue(anchorToml());
      fetchSpy
        .mockResolvedValueOnce(jsonResponse({ transaction: challenge }))
        .mockResolvedValueOnce(
          jsonResponse({ error: 'invalid challenge signature' }, false, 401),
        );

      const err = await service
        .initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(Sep10AuthError);
      expect((err as Sep10AuthError).phase).toBe('token_exchange');
    });

    it('throws Sep10AuthError when the challenge response has no transaction', async () => {
      resolveSpy.mockResolvedValue(anchorToml());
      fetchSpy.mockResolvedValueOnce(jsonResponse({}));

      const err = await service
        .initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(Sep10AuthError);
      expect((err as Sep10AuthError).phase).toBe('challenge_request');
    });

    it('throws Sep24InitiationError when the interactive endpoint fails', async () => {
      const challenge = buildChallenge(clientKeypair.publicKey());
      resolveSpy.mockResolvedValue(anchorToml());
      fetchSpy
        .mockResolvedValueOnce(jsonResponse({ transaction: challenge }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token-123' }))
        .mockResolvedValueOnce(
          jsonResponse({ error: 'anchor error' }, false, 500),
        );

      const err = await service
        .initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(Sep24InitiationError);
      expect((err as Sep24InitiationError).operation).toBe('deposit');
    });

    it('throws Sep24InitiationError when the anchor omits the interactive url', async () => {
      const challenge = buildChallenge(clientKeypair.publicKey());
      resolveSpy.mockResolvedValue(anchorToml());
      fetchSpy
        .mockResolvedValueOnce(jsonResponse({ transaction: challenge }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token-123' }))
        .mockResolvedValueOnce(jsonResponse({ id: 'dep-999' }));

      const err = await service
        .initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(Sep24InitiationError);
    });

    it('throws FiatRampsConfigurationError when the signing keypair is not configured', async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          FiatRampsService,
          { provide: AppConfigService, useValue: minimalAppConfig },
        ],
      }).compile();
      const unconfiguredService = module.get<FiatRampsService>(FiatRampsService);
      resolveSpy.mockResolvedValue(anchorToml());

      const err = await unconfiguredService
        .initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: 'GUSER123',
          anchorDomain: ANCHOR_DOMAIN,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(FiatRampsConfigurationError);
    });
  });

  describe('initiateWithdrawal', () => {
    it('runs the handshake and returns the anchor-provided withdrawal URL', async () => {
      const challenge = buildChallenge(clientKeypair.publicKey());
      const interactiveUrl = `${TRANSFER_URL}/withdraw?token=xyz789`;

      resolveSpy.mockResolvedValue(anchorToml());
      fetchSpy
        .mockResolvedValueOnce(jsonResponse({ transaction: challenge }))
        .mockResolvedValueOnce(jsonResponse({ token: 'jwt-token-456' }))
        .mockResolvedValueOnce(
          jsonResponse({
            id: 'wth-456',
            type: 'interactive_customer_info_needed',
            url: interactiveUrl,
          }),
        );

      const result = await service.initiateWithdrawal({
        assetCode: 'XLM',
        amount: 50,
        userAccount: 'GUSER123',
        anchorDomain: ANCHOR_DOMAIN,
      });

      expect(result).toEqual({
        status: 'success',
        transaction_id: 'wth-456',
        type: 'interactive_customer_info_needed',
        url: interactiveUrl,
      });

      const sep24Call = fetchSpy.mock.calls[2];
      expect(sep24Call[0]).toBe(`${TRANSFER_URL}/withdraw/interactive`);
      const sep24Init = sep24Call[1] as RequestInit;
      expect((sep24Init.headers as Record<string, string>).Authorization).toBe(
        'Bearer jwt-token-456',
      );
      const sep24Body = new URLSearchParams(sep24Init.body as string);
      expect(sep24Body.get('asset_code')).toBe('XLM');
      expect(sep24Body.get('amount')).toBe('50');
    });
  });
});
