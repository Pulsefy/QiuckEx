import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';

import {
  RuntimeConfigService,
} from '../src/runtime-config/runtime-config.service';
import { RuntimeConfigController } from '../src/runtime-config/runtime-config.controller';
import { FeatureFlagsService } from '../src/feature-flags/feature-flags.service';
import { ContractRegistryService } from '../src/contracts/contract-registry.service';
import { PreviewScopeService } from '../src/preview-scope/preview-scope.service';

describe('Runtime Config Endpoints', () => {
  let app: INestApplication;
  let mockRuntimeConfigService: jest.Mocked<Partial<RuntimeConfigService>>;

  const baseConfig = {
    environment: 'test',
    network: {
      network: 'testnet' as const,
      networkPassphrase: 'Test SDF Network ; September 2015',
      horizonUrl: 'https://horizon-testnet.stellar.org',
      sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
      sorobanRpcUrls: ['https://soroban-testnet.stellar.org'],
      explorerUrl: 'https://stellar.expert/explorer/testnet',
    },
    apiUrl: 'https://testnet-api.quickex.to',
    appVersion: '0.1.0',
    minAppVersion: '1.2.0',
    mobileVersionPolicy: {
      minSupportedVersion: '1.2.0',
      recommendedVersion: '1.3.0',
      latestVersion: '1.3.1',
      iosStoreUrl: 'https://apps.apple.com/app/quickex',
      androidStoreUrl: 'market://details?id=com.pulsefy.quickex',
      releaseNotes: ['Security fixes'],
    },
    contracts: {},
    featureFlags: [
      {
        key: 'bulk_invoicing_v2',
        name: 'Bulk Invoicing v2',
        enabled: true,
        killSwitch: false,
        rolloutPercentage: 100,
      },
    ],
    generatedAt: new Date().toISOString(),
    etag: 'W/"runtime-config-test-1"',
  };

  beforeAll(async () => {
    mockRuntimeConfigService = {
      getConfig: jest.fn(),
      validateConfig: jest.fn(),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [RuntimeConfigController],
      providers: [
        { provide: RuntimeConfigService, useValue: mockRuntimeConfigService },
      ],
    })
      .overrideProvider(FeatureFlagsService)
      .useValue({ getSnapshot: jest.fn() })
      .overrideProvider(ContractRegistryService)
      .useValue({ getRegistry: jest.fn() })
      .overrideProvider(PreviewScopeService)
      .useValue({ getScope: jest.fn() })
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ── Shared Testnet Bootstrap ─────────────────────────────────────────────

  it('GET /v1/runtime-config returns complete config for shared testnet', async () => {
    mockRuntimeConfigService.getConfig!.mockResolvedValue({
      ...baseConfig,
      contracts: {
        quickex: {
          contractId: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
          wasmHash: '0xabcdef1234567890',
          version: 1,
          schemaVersion: '1.0.0',
        },
      },
      featureFlags: [
        {
          key: 'bulk_invoicing_v2',
          name: 'Bulk Invoicing v2',
          enabled: true,
          killSwitch: false,
          rolloutPercentage: 100,
        },
        {
          key: 'testnet.contract_writes',
          name: 'Testnet Contract Writes',
          enabled: true,
          killSwitch: false,
          rolloutPercentage: 100,
        },
      ],
    });

    const response = await request(app.getHttpServer())
      .get('/v1/runtime-config')
      .expect(200);

    expect(response.body).toMatchObject({
      environment: 'test',
      network: {
        network: 'testnet',
        networkPassphrase: 'Test SDF Network ; September 2015',
      },
      contracts: {
        quickex: {
          contractId: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
        },
      },
      featureFlags: expect.arrayContaining([
        expect.objectContaining({ key: 'bulk_invoicing_v2' }),
        expect.objectContaining({ key: 'testnet.contract_writes' }),
      ]),
      appVersion: '0.1.0',
      minAppVersion: '1.2.0',
      mobileVersionPolicy: expect.objectContaining({
        minSupportedVersion: '1.2.0',
        recommendedVersion: '1.3.0',
      }),
    });
  });

  // ── Preview Environment ──────────────────────────────────────────────────

  it('GET /v1/runtime-config includes preview metadata with X-Preview-Scope', async () => {
    const futureDate = new Date(Date.now() + 3600000).toISOString();
    mockRuntimeConfigService.getConfig!.mockResolvedValue({
      ...baseConfig,
      apiUrl: 'https://preview-api.quickex.to',
      preview: {
        scopeId: 'pr-123',
        branchName: 'feature/new-ui',
        expiresAt: futureDate,
        valid: true,
      },
    });

    const response = await request(app.getHttpServer())
      .get('/v1/runtime-config')
      .set('X-Preview-Scope', 'pr-123')
      .expect(200);

    expect(response.body.preview).toBeDefined();
    expect(response.body.preview.scopeId).toBe('pr-123');
    expect(response.body.preview.branchName).toBe('feature/new-ui');
    expect(response.body.preview.valid).toBe(true);
    expect(response.body.apiUrl).toBe('https://preview-api.quickex.to');
  });

  // ── Minimal / Fallback Environment ───────────────────────────────────────

  it('GET /v1/runtime-config returns minimal config with fallbacks', async () => {
    mockRuntimeConfigService.getConfig!.mockResolvedValue({
      ...baseConfig,
      contracts: {},
      featureFlags: [],
    });

    const response = await request(app.getHttpServer())
      .get('/v1/runtime-config')
      .expect(200);

    expect(response.body.contracts).toEqual({});
    expect(response.body.featureFlags).toEqual([]);
    expect(response.body.network).toBeDefined();
    expect(response.body.apiUrl).toBeDefined();
  });

  // ── Cache Headers ────────────────────────────────────────────────────────

  it('GET /v1/runtime-config includes cache-control and ETag headers', async () => {
    mockRuntimeConfigService.getConfig!.mockResolvedValue(baseConfig);

    const response = await request(app.getHttpServer())
      .get('/v1/runtime-config')
      .expect(200);

    expect(response.headers['cache-control']).toBe('public, max-age=0, must-revalidate');
    expect(response.headers['etag']).toBeDefined();
  });

  it('GET /v1/runtime-config returns 304 when ETag matches', async () => {
    mockRuntimeConfigService.getConfig!.mockResolvedValue(baseConfig);

    const etag = 'W/"runtime-config-test-1"';

    await request(app.getHttpServer())
      .get('/v1/runtime-config')
      .set('If-None-Match', etag)
      .expect(304);
  });

  // ── Sensitive Data Exclusion ─────────────────────────────────────────────

  it('GET /v1/runtime-config does not expose sensitive fields', async () => {
    mockRuntimeConfigService.getConfig!.mockResolvedValue(baseConfig);

    const response = await request(app.getHttpServer())
      .get('/v1/runtime-config')
      .expect(200);

    expect(response.body).not.toHaveProperty('secrets');
    expect(response.body).not.toHaveProperty('database');
    expect(response.body).not.toHaveProperty('sentry');
    expect(response.body).not.toHaveProperty('apiKeys');

    const bodyStr = JSON.stringify(response.body);
    expect(bodyStr).not.toContain('secret');
    expect(bodyStr).not.toContain('private_key');
  });
});
