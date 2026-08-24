import { FiatRampsService, AnchorIntegrationError } from './fiat-ramps.service';
import { TomlFetcherService } from '../asset-metadata/toml-fetcher.service';
import { AppConfigService } from '../config/app-config.service';

jest.mock('@stellar/stellar-sdk', () => {
  return {
    Transaction: jest.fn().mockImplementation(() => ({
      sign: jest.fn(),
      toEnvelope: () => ({ toXDR: () => 'signed-xdr' }),
    })),
    Keypair: {
      fromSecret: jest.fn(() => ({
        publicKey: () => 'GFAKE',
      })),
    },
    Networks: { TESTNET: 'Test SDF Network ; September 2015' },
  };
});

describe('FiatRampsService (SEP-24 handshake)', () => {
  let service: FiatRampsService;
  let tomlFetcher: Partial<TomlFetcherService>;
  let config: Partial<AppConfigService>;
  const globalAny: any = global;

  beforeEach(() => {
    tomlFetcher = {
      fetchStellarToml: jest.fn(),
    };

    config = {
      get stellarSecretKey() {
        return 'SFAKEKEY';
      },
      get stellarNetworkPassphrase() {
        return 'Test SDF Network ; September 2015';
      },
    } as unknown as Partial<AppConfigService>;

    service = new FiatRampsService(tomlFetcher as TomlFetcherService, config as AppConfigService);
    globalAny.fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('initiates deposit via SEP-24 interactive flow when anchor responds correctly', async () => {
    (tomlFetcher.fetchStellarToml as jest.Mock).mockResolvedValue({
      TRANSFER_SERVER_SEP0024: 'https://anchor.example',
      WEB_AUTH_ENDPOINT: 'https://anchor.example/auth',
      CURRENCIES: [{ code: 'USDC' }],
    });

    // Sequence: challenge GET, auth POST, deposit POST
    (globalAny.fetch as jest.Mock)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ transaction: 'challenge-xdr' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'jwt-token' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ type: 'interactive_customer_info_needed', url: 'https://anchor.example/interactive' }) });

    const result = await service.initiateDeposit({ assetCode: 'USDC', amount: 10, userAccount: 'GUSER', anchorDomain: 'anchor.example' });

    expect(result).toBeDefined();
    expect(result.type).toBe('interactive_customer_info_needed');
    expect(result.url).toBe('https://anchor.example/interactive');
    expect(tomlFetcher.fetchStellarToml).toHaveBeenCalledWith('anchor.example');
  });

  it('throws when SEP-10 auth fails (auth endpoint returns non-OK)', async () => {
    (tomlFetcher.fetchStellarToml as jest.Mock).mockResolvedValue({
      TRANSFER_SERVER_SEP0024: 'https://anchor.example',
      WEB_AUTH_ENDPOINT: 'https://anchor.example/auth',
      CURRENCIES: [{ code: 'USDC' }],
    });

    (globalAny.fetch as jest.Mock)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ transaction: 'challenge-xdr' }) })
      .mockResolvedValueOnce({ ok: false, status: 401, text: async () => 'unauthorized' });

    await expect(
      service.initiateDeposit({ assetCode: 'USDC', amount: 5, userAccount: 'GUSER', anchorDomain: 'anchor.example' }),
    ).rejects.toBeInstanceOf(AnchorIntegrationError);
  });
});
