import { createServer, IncomingMessage, Server, ServerResponse } from 'http';
import { AddressInfo } from 'net';
import { Test, TestingModule } from '@nestjs/testing';
import { Keypair, Networks, WebAuth } from '@stellar/stellar-sdk';

import { AppConfigService } from '../config/app-config.service';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import {
  FiatRampsService,
  FIAT_RAMPS_SERVICE_OPTIONS,
} from './fiat-ramps.service';
import { Sep10AuthError, UnsupportedAssetError } from './errors';

const NETWORK_PASSPHRASE = Networks.TESTNET;
const HOME_DOMAIN_PREFIX = '127.0.0.1';

/** Stub anchor signing keypair (SIGNING_KEY in stellar.toml). */
const serverKeypair = Keypair.random();
/** Backend wallet keypair (STELLAR_SECRET_KEY / STELLAR_PUBLIC_KEY). */
const clientKeypair = Keypair.random();
const USER_ACCOUNT = Keypair.random().publicKey();

const mockAppConfig = {
  stellarSecretKey: clientKeypair.secret(),
  stellarPublicKey: clientKeypair.publicKey(),
  stellarNetworkPassphrase: NETWORK_PASSPHRASE,
};

/** Mock SEP-24 transaction repository (records are persisted after handshake). */
const mockSep24Repository = {
  create: jest.fn(),
};

interface StubAnchor {
  server: Server;
  port: number;
  close: () => Promise<void>;
}

function tomlText(port: number): string {
  const domain = `${HOME_DOMAIN_PREFIX}:${port}`;
  return [
    'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
    `WEB_AUTH_ENDPOINT = "http://${domain}/auth"`,
    `TRANSFER_SERVER_SEP0024 = "http://${domain}/transfer"`,
    `WEB_AUTH_DOMAIN = "${domain}"`,
    `SIGNING_KEY = "${serverKeypair.publicKey()}"`,
    '[[CURRENCIES]]',
    'code = "USDC"',
    `issuer = "${Keypair.random().publicKey()}"`,
    '[[CURRENCIES]]',
    'code = "XLM"',
    '',
  ].join('\n');
}

function send(
  res: ServerResponse,
  status: number,
  contentType: string,
  data: string,
): void {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(data);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk: Buffer) => {
      data += chunk.toString();
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function startServer(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve(port);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Spin up a stubbed anchor on an ephemeral port that speaks SEP-01, SEP-10
 * and SEP-24 against the real `@stellar/stellar-sdk` crypto.
 */
async function createStubAnchor(options: {
  failTokenExchange?: boolean;
} = {}): Promise<StubAnchor> {
  const failTokenExchange = options.failTokenExchange ?? false;
  const state = { port: 0 };
  const server = createServer((req, res) => {
    void handleRequest(req, res, () => state.port, failTokenExchange);
  });
  state.port = await startServer(server);
  return {
    server,
    port: state.port,
    close: () => closeServer(server),
  };
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  getPort: () => number,
  failTokenExchange: boolean,
): Promise<void> {
  const domain = `${HOME_DOMAIN_PREFIX}:${getPort()}`;
  const url = new URL(req.url ?? '/', `http://${domain}`);
  const method = req.method ?? 'GET';

  // SEP-01: serve stellar.toml
  if (method === 'GET' && url.pathname === '/.well-known/stellar.toml') {
    send(res, 200, 'application/toml', tomlText(getPort()));
    return;
  }

  // SEP-10: challenge request + token exchange
  if (method === 'POST' && url.pathname === '/auth') {
    const params = new URLSearchParams(await readBody(req));

    // Challenge request: { account }
    if (params.has('account') && !params.has('transaction')) {
      const challenge = WebAuth.buildChallengeTx(
        serverKeypair,
        params.get('account') as string,
        domain,
        300,
        NETWORK_PASSPHRASE,
        domain,
      );
      send(res, 200, 'application/json', JSON.stringify({ transaction: challenge }));
      return;
    }

    // Token exchange: { transaction }
    if (params.has('transaction')) {
      if (failTokenExchange) {
        send(
          res,
          401,
          'application/json',
          JSON.stringify({ error: 'invalid challenge signature' }),
        );
        return;
      }
      try {
        WebAuth.verifyChallengeTxSigners(
          params.get('transaction') as string,
          serverKeypair.publicKey(),
          NETWORK_PASSPHRASE,
          [clientKeypair.publicKey()],
          [domain],
          domain,
        );
      } catch {
        send(
          res,
          401,
          'application/json',
          JSON.stringify({ error: 'invalid challenge signature' }),
        );
        return;
      }
      send(res, 200, 'application/json', JSON.stringify({ token: 'stub-jwt' }));
      return;
    }

    send(res, 400, 'application/json', JSON.stringify({ error: 'missing account or transaction' }));
    return;
  }

  // SEP-24: interactive initiation (deposit / withdraw)
  if (method === 'POST' && url.pathname.startsWith('/transfer/')) {
    if (req.headers.authorization !== 'Bearer stub-jwt') {
      send(res, 401, 'application/json', JSON.stringify({ error: 'unauthorized' }));
      return;
    }

    const params = new URLSearchParams(await readBody(req));
    const assetCode = params.get('asset_code') ?? '';
    const operation = url.pathname.endsWith('/withdraw/interactive')
      ? 'withdraw'
      : 'deposit';
    const interactiveUrl = `http://${domain}/interactive/${operation}?token=stub-jwt&asset=${assetCode}`;

    send(
      res,
      200,
      'application/json',
      JSON.stringify({
        id: operation === 'deposit' ? 'dep-1' : 'wth-1',
        type: 'interactive_customer_info_needed',
        url: interactiveUrl,
      }),
    );
    return;
  }

  send(res, 404, 'application/json', JSON.stringify({ error: 'not found' }));
}

describe('FiatRampsService (stub anchor integration)', () => {
  let service: FiatRampsService;
  let stub: StubAnchor;

  beforeEach(async () => {
    stub = await createStubAnchor();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FiatRampsService,
        { provide: AppConfigService, useValue: mockAppConfig },
        { provide: Sep24TransactionRepository, useValue: mockSep24Repository },
        {
          // Short TOML timeout keeps the SDK's CancelToken timers from
          // lingering past Jest's exit grace period. Prod default is 5000ms.
          provide: FIAT_RAMPS_SERVICE_OPTIONS,
          useValue: { allowHttp: true, tomlTimeoutMs: 250 },
        },
      ],
    }).compile();

    service = module.get<FiatRampsService>(FiatRampsService);
    mockSep24Repository.create.mockReset().mockResolvedValue({ id: 'record-1' });
  });

  afterEach(async () => {
    await stub.close();
  });

  it('completes the end-to-end deposit handshake against the stub anchor', async () => {
    const domain = `${HOME_DOMAIN_PREFIX}:${stub.port}`;

    const result = await service.initiateDeposit({
      assetCode: 'USDC',
      amount: 100,
      userAccount: USER_ACCOUNT,
      anchorDomain: domain,
    });

    expect(result).toEqual({
      status: 'success',
      transaction_id: 'dep-1',
      internal_id: 'record-1',
      type: 'interactive_customer_info_needed',
      url: `http://${domain}/interactive/deposit?token=stub-jwt&asset=USDC`,
    });

    // The handshake result is persisted so the SEP-24 polling worker can track it.
    expect(mockSep24Repository.create).toHaveBeenCalledWith(
      expect.objectContaining({
        anchor_transaction_id: 'dep-1',
        type: 'deposit',
        asset_code: 'USDC',
        interactive_url: `http://${domain}/interactive/deposit?token=stub-jwt&asset=USDC`,
      }),
    );
  });

  it('completes the end-to-end withdrawal handshake against the stub anchor', async () => {
    const domain = `${HOME_DOMAIN_PREFIX}:${stub.port}`;

    const result = await service.initiateWithdrawal({
      assetCode: 'XLM',
      amount: 50,
      userAccount: USER_ACCOUNT,
      anchorDomain: domain,
    });

    expect(result).toEqual({
      status: 'success',
      transaction_id: 'wth-1',
      internal_id: 'record-1',
      type: 'interactive_customer_info_needed',
      url: `http://${domain}/interactive/withdraw?token=stub-jwt&asset=XLM`,
    });
  });

  it('rejects assets the anchor does not list in stellar.toml', async () => {
    const domain = `${HOME_DOMAIN_PREFIX}:${stub.port}`;

    const err = await service
      .initiateDeposit({
        assetCode: 'EURC',
        amount: 10,
        userAccount: USER_ACCOUNT,
        anchorDomain: domain,
      })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(UnsupportedAssetError);
    expect((err as UnsupportedAssetError).assetCode).toBe('EURC');
  });

  it('throws Sep10AuthError when the anchor rejects the signed challenge', async () => {
    const failingStub = await createStubAnchor({ failTokenExchange: true });
    try {
      const err = await service
        .initiateDeposit({
          assetCode: 'USDC',
          amount: 10,
          userAccount: USER_ACCOUNT,
          anchorDomain: `${HOME_DOMAIN_PREFIX}:${failingStub.port}`,
        })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(Sep10AuthError);
      expect((err as Sep10AuthError).phase).toBe('token_exchange');
    } finally {
      await failingStub.close();
    }
  });

  it('throws AnchorNotFoundError when the anchor is unreachable', async () => {
    const err = await service
      .initiateDeposit({
        assetCode: 'USDC',
        amount: 10,
        userAccount: USER_ACCOUNT,
        anchorDomain: '127.0.0.1:1', // nothing listening on port 1
      })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(Error);
    expect((err as Error).name).toBe('AnchorNotFoundError');
  });
});
