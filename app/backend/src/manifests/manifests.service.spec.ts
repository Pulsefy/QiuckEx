import { Test, TestingModule } from '@nestjs/testing';
import { ManifestsService } from './manifests.service';
import { EnvironmentManifestDto } from './dto/manifest-diff.dto';

describe('ManifestsService', () => {
  let service: ManifestsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ManifestsService],
    }).compile();

    service = module.get<ManifestsService>(ManifestsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  const baseManifest: EnvironmentManifestDto = {
    contracts: {
      market: { id: 'market-123', wasmHash: 'hash-abc' },
      escrow: { id: 'escrow-456', wasmHash: 'hash-def' },
    },
    urls: {
      api: 'https://api.testnet.internal',
      docs: 'https://docs.testnet.internal',
    },
    featureFlags: {
      enableDisputes: true,
      betaUI: false,
    },
  };

  it('returns unchanged for identical manifests', () => {
    const diff = service.diffManifests(baseManifest, baseManifest);

    expect(diff.contracts.market.status).toBe('unchanged');
    expect(diff.contracts.escrow.status).toBe('unchanged');
    expect(diff.urls.api.status).toBe('unchanged');
    expect(diff.featureFlags.enableDisputes.status).toBe('unchanged');
  });

  it('detects added, removed, and modified fields', () => {
    const targetManifest: EnvironmentManifestDto = {
      contracts: {
        market: { id: 'market-123', wasmHash: 'hash-xyz' }, // modified wasmHash
        token: { id: 'token-789', wasmHash: 'hash-ghi' }, // added
      },
      urls: {
        api: 'https://api.preview.internal', // modified
      },
      featureFlags: {
        enableDisputes: true, // unchanged
        betaUI: true, // modified
        newFeature: true, // added
      },
    };

    const diff = service.diffManifests(baseManifest, targetManifest);

    expect(diff.contracts.market.status).toBe('modified');
    expect(diff.contracts.escrow.status).toBe('removed');
    expect(diff.contracts.token.status).toBe('added');
    expect(diff.urls.api.status).toBe('modified');
    expect(diff.urls.docs.status).toBe('removed');
    expect(diff.featureFlags.betaUI.status).toBe('modified');
    expect(diff.featureFlags.newFeature.status).toBe('added');
  });

  it('handles missing sections gracefully', () => {
    const targetManifest: EnvironmentManifestDto = {};

    const diff = service.diffManifests(baseManifest, targetManifest);

    expect(diff.contracts.market.status).toBe('removed');
    expect(diff.urls.api.status).toBe('removed');
    expect(diff.featureFlags.betaUI.status).toBe('removed');
  });
});
