/**
 * AnchorClientService – Unit Tests
 *
 * Covers the three pillars of the SEP-24 anchor handshake:
 *
 *   1. **Capability Discovery** — stellar.toml parsing, missing fields, network errors
 *   2. **SEP-10 Authentication** — challenge-response flow, signing, error paths
 *   3. **SEP-24 Initiation** — interactive endpoint POST, error handling, response parsing
 *
 * All external HTTP calls are stubbed via global `fetch` mocks.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { Keypair } from '@stellar/stellar-sdk';
import { AnchorClientService } from './anchor-client.service';
import {
  AnchorDiscoveryError,
  Sep10AuthError,
  Sep24InitiationError,
} from './types/sep24.types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Generate a deterministic test keypair. */
function testKeypair(): Keypair {
  return Keypair.fromSecret(
    'SCX6A3F3XCFW7IT3MY6DSZWULY4U6O5PZHILY3SAPU4QZIHUEO7JZLLS',
  );
}

// ─── Fetch mock helpers ───────────────────────────────────────────────────────

const originalFetch = global.fetch;

function mockFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  global.fetch = jest.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = typeof url === 'string' ? url : url.toString();
    return handler(urlStr, init);
  }) as unknown as typeof fetch;
}

function restoreFetch() {
  global.fetch = originalFetch;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain' },
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('AnchorClientService', () => {
  let service: AnchorClientService;

  const ANCHOR_DOMAIN = 'test.anchor.org';

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [AnchorClientService],
    }).compile();

    service = module.get<AnchorClientService>(AnchorClientService);
  });

  afterEach(() => {
    restoreFetch();
  });

  // ─── discoverAnchorCapabilities ──────────────────────────────────────────

  describe('discoverAnchorCapabilities', () => {
    const TOML_CONTENT = `
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
TRANSFER_SERVER_SEP0024 = "https://test.anchor.org/sep24"
TRANSFER_SERVER_SEP0010 = "https://test.anchor.org/auth"

[[CURRENCIES]]
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2K34P4D5NXJ6Z4GJ5B7G"

[[CURRENCIES]]
code = "EURC"
issuer = "GBNZILSTVQZ4R7IKQDGHYGY2Q45GJT5TTW3EHBQK7UL3UBFTPDP52GZP"
`;

    it('parses stellar.toml and returns anchor capabilities', async () => {
      mockFetch((url) => {
        expect(url).toBe(`https://${ANCHOR_DOMAIN}/.well-known/stellar.toml`);
        return textResponse(TOML_CONTENT);
      });

      const caps = await service.discoverAnchorCapabilities(ANCHOR_DOMAIN);

      expect(caps).toEqual({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['USDC', 'EURC'],
      });
    });

    it('strips leading scheme from domain', async () => {
      mockFetch(() => textResponse(TOML_CONTENT));

      const caps = await service.discoverAnchorCapabilities(`https://${ANCHOR_DOMAIN}`);

      expect(caps.transferServer).toBe('https://test.anchor.org/sep24');
    });

    it('throws AnchorDiscoveryError when stellar.toml returns HTTP error', async () => {
      mockFetch(() => textResponse('Not Found', 404));

      await expect(service.discoverAnchorCapabilities(ANCHOR_DOMAIN))
        .rejects.toThrow(AnchorDiscoveryError);
    });

    it('throws AnchorDiscoveryError on network timeout', async () => {
      mockFetch(() => { throw Object.assign(new Error('Aborted'), { name: 'AbortError' }); });

      await expect(service.discoverAnchorCapabilities(ANCHOR_DOMAIN))
        .rejects.toThrow(AnchorDiscoveryError);
    });

    it('throws AnchorDiscoveryError when TRANSFER_SERVER_SEP0024 is missing', async () => {
      const incompleteToml = `
TRANSFER_SERVER_SEP0010 = "https://test.anchor.org/auth"
`;
      mockFetch(() => textResponse(incompleteToml));

      await expect(service.discoverAnchorCapabilities(ANCHOR_DOMAIN))
        .rejects.toThrow(/missing TRANSFER_SERVER_SEP0024/);
    });

    it('throws AnchorDiscoveryError when TRANSFER_SERVER_SEP0010 is missing', async () => {
      const incompleteToml = `
TRANSFER_SERVER_SEP0024 = "https://test.anchor.org/sep24"
`;
      mockFetch(() => textResponse(incompleteToml));

      await expect(service.discoverAnchorCapabilities(ANCHOR_DOMAIN))
        .rejects.toThrow(/missing TRANSFER_SERVER_SEP0010/);
    });

    it('returns empty supportedAssets when no [[CURRENCIES]] blocks exist', async () => {
      const tomlNoCurrencies = `
TRANSFER_SERVER_SEP0024 = "https://test.anchor.org/sep24"
TRANSFER_SERVER_SEP0010 = "https://test.anchor.org/auth"
`;
      mockFetch(() => textResponse(tomlNoCurrencies));

      const caps = await service.discoverAnchorCapabilities(ANCHOR_DOMAIN);

      expect(caps.supportedAssets).toEqual([]);
    });

    it('deduplicates asset codes from multiple [[CURRENCIES]] blocks', async () => {
      const tomlDupes = `
TRANSFER_SERVER_SEP0024 = "https://test.anchor.org/sep24"
TRANSFER_SERVER_SEP0010 = "https://test.anchor.org/auth"

[[CURRENCIES]]
code = "USDC"

[[CURRENCIES]]
code = "USDC"
`;
      mockFetch(() => textResponse(tomlDupes));

      const caps = await service.discoverAnchorCapabilities(ANCHOR_DOMAIN);

      expect(caps.supportedAssets).toEqual(['USDC']);
    });
  });

  // ─── performSep10Auth ────────────────────────────────────────────────────

  describe('performSep10Auth', () => {
    const AUTH_SERVER = 'https://test.anchor.org/auth';
    const NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

    it('performs full challenge-response flow and returns JWT', async () => {
      const keypair = testKeypair();
      const publicKey = keypair.publicKey();

      const fakeJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

      // Build a real ManageData challenge transaction (the standard SEP-10 challenge).
      // This creates a valid XDR that TransactionBuilder.fromXDR can parse.
      const { TransactionBuilder, Operation } = await import('@stellar/stellar-sdk');
      const { Account } = await import('@stellar/stellar-base');

      const challengeAccount = new Account(publicKey, '0');
      const challengeTx = new TransactionBuilder(
        challengeAccount,
        { fee: '100', networkPassphrase: NETWORK_PASSPHRASE },
      )
        .addOperation(
          Operation.manageData({
            name: `auth ${publicKey}`,
            value: Buffer.alloc(32, 0x42),
          }),
        )
        .setTimeout(300)
        .build();

      const challengeXdr = challengeTx.toXDR();

      let callCount = 0;
      mockFetch(async (url, init) => {
        callCount++;
        expect(url).toBe(AUTH_SERVER);

        if (callCount === 1) {
          // Challenge request
          const body = JSON.parse(init!.body as string);
          expect(body.account).toBe(publicKey);
          return jsonResponse({
            transaction: challengeXdr,
            network_passphrase: NETWORK_PASSPHRASE,
          });
        }

        // Submit signed challenge
        const body = JSON.parse(init!.body as string);
        expect(body.account).toBe(publicKey);
        expect(typeof body.transaction).toBe('string');
        expect(body.transaction).not.toBe(challengeXdr); // should be different (signed)

        return jsonResponse({ token: fakeJwt });
      });

      const jwt = await service.performSep10Auth(
        ANCHOR_DOMAIN,
        AUTH_SERVER,
        keypair,
        NETWORK_PASSPHRASE,
      );

      expect(jwt).toBe(fakeJwt);
    });

    it('throws Sep10AuthError when challenge request returns HTTP error', async () => {
      const keypair = testKeypair();

      mockFetch(() => jsonResponse({ error: 'invalid account' }, 400));

      await expect(
        service.performSep10Auth(ANCHOR_DOMAIN, AUTH_SERVER, keypair, NETWORK_PASSPHRASE),
      ).rejects.toThrow(Sep10AuthError);
    });

    it('throws Sep10AuthError when challenge response is missing transaction field', async () => {
      const keypair = testKeypair();

      mockFetch(() => jsonResponse({}));

      await expect(
        service.performSep10Auth(ANCHOR_DOMAIN, AUTH_SERVER, keypair, NETWORK_PASSPHRASE),
      ).rejects.toThrow(Sep10AuthError);
    });

    it('throws Sep10AuthError on network timeout during challenge', async () => {
      const keypair = testKeypair();

      mockFetch(() => { throw Object.assign(new Error('Aborted'), { name: 'AbortError' }); });

      await expect(
        service.performSep10Auth(ANCHOR_DOMAIN, AUTH_SERVER, keypair, NETWORK_PASSPHRASE),
      ).rejects.toThrow(Sep10AuthError);
    });

    it('throws Sep10AuthError when auth submission returns HTTP error', async () => {
      const keypair = testKeypair();
      const { TransactionBuilder, Operation } = await import('@stellar/stellar-sdk');
      const { Account } = await import('@stellar/stellar-base');

      const challengeAccount = new Account(keypair.publicKey(), '0');
      const challengeTx = new TransactionBuilder(
        challengeAccount,
        { fee: '100', networkPassphrase: NETWORK_PASSPHRASE },
      )
        .addOperation(
          Operation.manageData({
            name: `auth ${keypair.publicKey()}`,
            value: Buffer.alloc(32, 0x42),
          }),
        )
        .setTimeout(300)
        .build();

      const challengeXdr = challengeTx.toXDR();

      let callCount = 0;
      mockFetch(async () => {
        callCount++;

        if (callCount === 1) {
          // Challenge succeeds
          return jsonResponse({
            transaction: challengeXdr,
            network_passphrase: NETWORK_PASSPHRASE,
          });
        }

        // Auth submission fails
        return jsonResponse({ error: 'invalid signature' }, 401);
      });

      await expect(
        service.performSep10Auth(ANCHOR_DOMAIN, AUTH_SERVER, keypair, NETWORK_PASSPHRASE),
      ).rejects.toThrow(Sep10AuthError);
    });

    it('throws Sep10AuthError when auth response is missing token field', async () => {
      const keypair = testKeypair();
      const { TransactionBuilder, Operation } = await import('@stellar/stellar-sdk');
      const { Account } = await import('@stellar/stellar-base');

      const challengeAccount = new Account(keypair.publicKey(), '0');
      const challengeTx = new TransactionBuilder(
        challengeAccount,
        { fee: '100', networkPassphrase: NETWORK_PASSPHRASE },
      )
        .addOperation(
          Operation.manageData({
            name: `auth ${keypair.publicKey()}`,
            value: Buffer.alloc(32, 0x42),
          }),
        )
        .setTimeout(300)
        .build();

      const challengeXdr = challengeTx.toXDR();

      let callCount = 0;
      mockFetch(async () => {
        callCount++;

        if (callCount === 1) {
          return jsonResponse({
            transaction: challengeXdr,
            network_passphrase: NETWORK_PASSPHRASE,
          });
        }

        return jsonResponse({});
      });

      await expect(
        service.performSep10Auth(ANCHOR_DOMAIN, AUTH_SERVER, keypair, NETWORK_PASSPHRASE),
      ).rejects.toThrow(Sep10AuthError);
    });
  });

  // ─── initiateSep24Transaction ────────────────────────────────────────────

  describe('initiateSep24Transaction', () => {
    const TRANSFER_SERVER = 'https://test.anchor.org/sep24';
    const JWT = 'test-jwt-token';

    it('initiates deposit and returns interactive URL from anchor response', async () => {
      const interactiveUrl = 'https://test.anchor.org/sep24/interactive/form/abc123';

      mockFetch(async (url, init) => {
        expect(url).toBe(`${TRANSFER_SERVER}/transactions/deposit/interactive`);

        const body = JSON.parse(init!.body as string);
        expect(body.asset_code).toBe('USDC');
        expect(body.account).toBe('GABC123');
        expect(body.amount).toBe('100.00');

        // Verify Authorization header
        expect(init!.headers).toMatchObject({
          Authorization: `Bearer ${JWT}`,
        });

        return jsonResponse({
          type: 'interactive_customer_info_needed',
          url: interactiveUrl,
          id: 'anchor-tx-001',
          message: 'Please complete the KYC form',
        });
      });

      const result = await service.initiateSep24Transaction({
        anchorDomain: ANCHOR_DOMAIN,
        jwt: JWT,
        transferServer: TRANSFER_SERVER,
        type: 'deposit',
        assetCode: 'USDC',
        account: 'GABC123',
        amount: '100.00',
      });

      expect(result).toEqual({
        type: 'interactive_customer_info_needed',
        url: interactiveUrl,
        id: 'anchor-tx-001',
        message: 'Please complete the KYC form',
      });
    });

    it('initiates withdrawal correctly', async () => {
      const interactiveUrl = 'https://test.anchor.org/sep24/interactive/form/def456';

      mockFetch(async (url, init) => {
        expect(url).toBe(`${TRANSFER_SERVER}/transactions/withdrawal/interactive`);

        const body = JSON.parse(init!.body as string);
        expect(body.asset_code).toBe('EURC');
        expect(body.account).toBe('GDEF456');
        expect(body.amount).toBe('50.00');

        return jsonResponse({
          type: 'interactive_customer_info_needed',
          url: interactiveUrl,
        });
      });

      const result = await service.initiateSep24Transaction({
        anchorDomain: ANCHOR_DOMAIN,
        jwt: JWT,
        transferServer: TRANSFER_SERVER,
        type: 'withdrawal',
        assetCode: 'EURC',
        account: 'GDEF456',
        amount: '50.00',
      });

      expect(result.url).toBe(interactiveUrl);
      expect(result.type).toBe('interactive_customer_info_needed');
    });

    it('includes optional fields (assetIssuer, returnUrl, memo, memoType) in request body', async () => {
      mockFetch(async (url, init) => {
        const body = JSON.parse(init!.body as string);
        expect(body.asset_issuer).toBe('GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2K34P4D5NXJ6Z4GJ5B7G');
        expect(body.return_url).toBe('https://quickex.app/return');
        expect(body.memo).toBe('test-memo');
        expect(body.memo_type).toBe('text');

        return jsonResponse({
          type: 'interactive_customer_info_needed',
          url: 'https://test.anchor.org/sep24/interactive/form/ghi789',
        });
      });

      await service.initiateSep24Transaction({
        anchorDomain: ANCHOR_DOMAIN,
        jwt: JWT,
        transferServer: TRANSFER_SERVER,
        type: 'deposit',
        assetCode: 'USDC',
        account: 'GABC123',
        assetIssuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2K34P4D5NXJ6Z4GJ5B7G',
        returnUrl: 'https://quickex.app/return',
        memo: 'test-memo',
        memoType: 'text',
      });
    });

    it('omits undefined optional fields from request body', async () => {
      mockFetch(async (url, init) => {
        const body = JSON.parse(init!.body as string);
        expect(body).not.toHaveProperty('amount');
        expect(body).not.toHaveProperty('asset_issuer');
        expect(body).not.toHaveProperty('return_url');
        expect(body).not.toHaveProperty('memo');
        expect(body).not.toHaveProperty('memo_type');

        return jsonResponse({
          type: 'interactive_customer_info_needed',
          url: 'https://test.anchor.org/sep24/interactive/form/minimal',
        });
      });

      await service.initiateSep24Transaction({
        anchorDomain: ANCHOR_DOMAIN,
        jwt: JWT,
        transferServer: TRANSFER_SERVER,
        type: 'deposit',
        assetCode: 'USDC',
        account: 'GABC123',
      });
    });

    it('throws Sep24InitiationError on network error', async () => {
      mockFetch(() => {
        throw Object.assign(new Error('Connection refused'), { name: 'TypeError' });
      });

      await expect(
        service.initiateSep24Transaction({
          anchorDomain: ANCHOR_DOMAIN,
          jwt: JWT,
          transferServer: TRANSFER_SERVER,
          type: 'deposit',
          assetCode: 'USDC',
          account: 'GABC123',
        }),
      ).rejects.toThrow(Sep24InitiationError);
    });

    it('throws Sep24InitiationError with 400 status for unsupported asset', async () => {
      mockFetch(() => jsonResponse({ error: 'unsupported asset XYZ' }, 400));

      await expect(
        service.initiateSep24Transaction({
          anchorDomain: ANCHOR_DOMAIN,
          jwt: JWT,
          transferServer: TRANSFER_SERVER,
          type: 'deposit',
          assetCode: 'XYZ',
          account: 'GABC123',
        }),
      ).rejects.toThrow(/unsupported asset or bad request/);
    });

    it('throws Sep24InitiationError on non-200 HTTP response', async () => {
      mockFetch(() => jsonResponse({ error: 'anchor unavailable' }, 503));

      await expect(
        service.initiateSep24Transaction({
          anchorDomain: ANCHOR_DOMAIN,
          jwt: JWT,
          transferServer: TRANSFER_SERVER,
          type: 'deposit',
          assetCode: 'USDC',
          account: 'GABC123',
        }),
      ).rejects.toThrow(Sep24InitiationError);
    });

    it('throws Sep24InitiationError when response type is not interactive_customer_info_needed', async () => {
      mockFetch(() =>
        jsonResponse({
          type: 'non_interactive',
          url: 'https://test.anchor.org/sep24/interactive/form/xyz',
        }),
      );

      await expect(
        service.initiateSep24Transaction({
          anchorDomain: ANCHOR_DOMAIN,
          jwt: JWT,
          transferServer: TRANSFER_SERVER,
          type: 'deposit',
          assetCode: 'USDC',
          account: 'GABC123',
        }),
      ).rejects.toThrow(/unexpected response type/);
    });

    it('throws Sep24InitiationError when response is missing URL', async () => {
      mockFetch(() =>
        jsonResponse({
          type: 'interactive_customer_info_needed',
          // url is missing
        }),
      );

      await expect(
        service.initiateSep24Transaction({
          anchorDomain: ANCHOR_DOMAIN,
          jwt: JWT,
          transferServer: TRANSFER_SERVER,
          type: 'deposit',
          assetCode: 'USDC',
          account: 'GABC123',
        }),
      ).rejects.toThrow(/missing interactive URL/);
    });

    it('throws Sep24InitiationError when anchor returns non-JSON response', async () => {
      mockFetch(() => new Response('Internal Server Error', { status: 500 }));

      await expect(
        service.initiateSep24Transaction({
          anchorDomain: ANCHOR_DOMAIN,
          jwt: JWT,
          transferServer: TRANSFER_SERVER,
          type: 'deposit',
          assetCode: 'USDC',
          account: 'GABC123',
        }),
      ).rejects.toThrow(Sep24InitiationError);
    });

    it('strips trailing slash from transferServer URL', async () => {
      mockFetch(async (url) => {
        // Should not have double slash
        expect(url).toBe(`${TRANSFER_SERVER}/transactions/deposit/interactive`);

        return jsonResponse({
          type: 'interactive_customer_info_needed',
          url: 'https://test.anchor.org/sep24/interactive/form/noslash',
        });
      });

      await service.initiateSep24Transaction({
        anchorDomain: ANCHOR_DOMAIN,
        jwt: JWT,
        transferServer: `${TRANSFER_SERVER}/`,
        type: 'deposit',
        assetCode: 'USDC',
        account: 'GABC123',
      });
    });
  });

  // ─── resolveSep24TransferServer (legacy) ─────────────────────────────────

  describe('resolveSep24TransferServer (legacy)', () => {
    it('returns transfer server URL on success', async () => {
      mockFetch(() => textResponse(`
TRANSFER_SERVER_SEP0024 = "https://test.anchor.org/sep24"
TRANSFER_SERVER_SEP0010 = "https://test.anchor.org/auth"
`));

      const result = await service.resolveSep24TransferServer(ANCHOR_DOMAIN);

      expect(result).toBe('https://test.anchor.org/sep24');
    });

    it('returns null on failure', async () => {
      mockFetch(() => textResponse('Not Found', 404));

      const result = await service.resolveSep24TransferServer(ANCHOR_DOMAIN);

      expect(result).toBeNull();
    });
  });

  // ─── pollTransaction ─────────────────────────────────────────────────────

  describe('pollTransaction', () => {
    it('returns success when anchor responds with valid transaction data', async () => {
      mockFetch(() =>
        jsonResponse({
          transaction: {
            id: 'anchor-tx-1',
            kind: 'deposit',
            status: 'pending_anchor',
          },
        }),
      );

      const result = await service.pollTransaction({
        anchorDomain: ANCHOR_DOMAIN,
        transactionId: 'anchor-tx-1',
      });

      expect(result.success).toBe(true);
      expect(result.data?.transaction.status).toBe('pending_anchor');
    });

    it('returns failure when anchor HTTP errors', async () => {
      mockFetch(() => jsonResponse({ error: 'not found' }, 404));

      const result = await service.pollTransaction({
        anchorDomain: ANCHOR_DOMAIN,
        transactionId: 'anchor-tx-1',
      });

      expect(result.success).toBe(false);
      expect(result.httpStatus).toBe(404);
    });

    it('returns failure on network error', async () => {
      mockFetch(() => { throw new Error('timeout'); });

      const result = await service.pollTransaction({
        anchorDomain: ANCHOR_DOMAIN,
        transactionId: 'anchor-tx-1',
      });

      expect(result.success).toBe(false);
      expect(result.httpStatus).toBeNull();
    });

    it('returns failure when response is missing required fields', async () => {
      mockFetch(() => jsonResponse({ transaction: { id: 'tx-1' } })); // missing status

      const result = await service.pollTransaction({
        anchorDomain: ANCHOR_DOMAIN,
        transactionId: 'anchor-tx-1',
      });

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/missing required fields/);
    });
  });
});
