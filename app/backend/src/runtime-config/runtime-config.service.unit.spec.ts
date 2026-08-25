import { Test, TestingModule } from "@nestjs/testing";
import { ConfigService } from "@nestjs/config";

import { AppConfigService } from "../config";
import { ContractRegistryService } from "../contracts/contract-registry.service";
import { FeatureFlagsService } from "../feature-flags/feature-flags.service";
import { PreviewScopeService } from "../preview-scope/preview-scope.service";
import { RuntimeConfigService } from "./runtime-config.service";

describe("RuntimeConfigService", () => {
  let service: RuntimeConfigService;
  let mockAppConfigService: jest.Mocked<Partial<AppConfigService>>;
  let mockConfigService: jest.Mocked<Partial<ConfigService>>;
  let mockFeatureFlagsService: jest.Mocked<Partial<FeatureFlagsService>>;
  let mockContractRegistryService: jest.Mocked<
    Partial<ContractRegistryService>
  >;
  let mockPreviewScopeService: jest.Mocked<Partial<PreviewScopeService>>;

  beforeEach(async () => {
    mockConfigService = {
      get: jest.fn(),
    };

    mockAppConfigService = {
      network: "testnet",
      nodeEnv: "test",
      environmentName: undefined,
      isMainnet: false,
      isStaging: false,
      publicApiUrl: undefined,
      mobileMinSupportedVersion: "1.2.0",
      mobileRecommendedVersion: "1.3.0",
      mobileLatestVersion: "1.3.1",
      mobileIosStoreUrl: "https://apps.apple.com/app/quickex",
      mobileAndroidStoreUrl: "market://details?id=com.pulsefy.quickex",
      mobileReleaseNotes: ["Security fixes", "Contract registry compatibility"],
    };

    mockFeatureFlagsService = {
      getSnapshot: jest.fn(),
    };

    mockContractRegistryService = {
      getRegistry: jest.fn(),
    };

    mockPreviewScopeService = {
      getScope: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RuntimeConfigService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: AppConfigService, useValue: mockAppConfigService },
        { provide: FeatureFlagsService, useValue: mockFeatureFlagsService },
        {
          provide: ContractRegistryService,
          useValue: mockContractRegistryService,
        },
        { provide: PreviewScopeService, useValue: mockPreviewScopeService },
      ],
    }).compile();

    service = module.get<RuntimeConfigService>(RuntimeConfigService);
    jest.clearAllMocks();

    mockConfigService.get!.mockImplementation((key: string) => {
      if (key === "stellar") {
        return {
          network: "testnet",
          networkPassphrase: "Test SDF Network ; September 2015",
          horizonBaseUrl: "https://horizon-testnet.stellar.org",
          sorobanRpcUrl: "https://soroban-testnet.stellar.org",
          sorobanRpcUrls: ["https://soroban-testnet.stellar.org"],
          explorerUrl: "https://stellar.expert/explorer/testnet",
        };
      }
      return undefined;
    });
  });

  // ── Shared / Testnet Environment ─────────────────────────────────────────

  it("returns complete config for shared testnet environment", async () => {
    mockFeatureFlagsService.getSnapshot!.mockResolvedValue({
      metadata: {
        source: "store",
        storeAvailable: true,
        flagCount: 2,
        sensitiveFlagCount: 0,
        timestamp: new Date().toISOString(),
      },
      flags: [
        {
          key: "bulk_invoicing_v2",
          name: "Bulk Invoicing v2",
          description: "",
          enabled: true,
          killSwitch: false,
          rolloutPercentage: 100,
          environments: ["development", "test", "production"],
          updatedAt: new Date().toISOString(),
          updatedBy: "bootstrap",
        },
        {
          key: "testnet.contract_writes",
          name: "Testnet Contract Writes",
          description: "",
          enabled: true,
          killSwitch: false,
          rolloutPercentage: 100,
          environments: ["development", "test", "production"],
          updatedAt: new Date().toISOString(),
          updatedBy: "bootstrap",
        },
      ],
    });

    mockContractRegistryService.getRegistry!.mockResolvedValue({
      network: "testnet",
      authoritative: true,
      version: 2,
      etag: 'W/"contract-registry-testnet-2"',
      data: {
        quickex: {
          id: "CD2J6K7T3YJ77QXZP3EXAMPLE",
          wasmHash: "0xabcdef1234567890",
          version: 1,
          schemaVersion: "1.0.0",
          schemaCompatibility: { min: "1.0.0", max: "2.0.0" },
          networkPassphrase: "Test SDF Network ; September 2015",
          deploymentId: "deploy-001",
          initParams: {},
          metadata: {},
          updatedAt: new Date().toISOString(),
        },
      },
    });

    const config = await service.getConfig();

    expect(config.environment).toBe("test");
    expect(config.network.network).toBe("testnet");
    expect(config.network.networkPassphrase).toBe(
      "Test SDF Network ; September 2015",
    );
    expect(config.network.horizonUrl).toBe(
      "https://horizon-testnet.stellar.org",
    );
    expect(config.network.sorobanRpcUrl).toBe(
      "https://soroban-testnet.stellar.org",
    );
    expect(config.network.sorobanRpcUrls).toHaveLength(1);
    expect(config.network.explorerUrl).toContain("/testnet");

    expect(config.contracts).toHaveProperty("quickex");
    expect(config.contracts.quickex.contractId).toBe(
      "CD2J6K7T3YJ77QXZP3EXAMPLE",
    );

    expect(config.featureFlags).toHaveLength(2);
    expect(config.featureFlags[0].key).toBe("bulk_invoicing_v2");
    expect(config.featureFlags[0].enabled).toBe(true);

    expect(config.appVersion).toBe("0.1.0");
    expect(config.minAppVersion).toBe("1.2.0");
    expect(config.mobileVersionPolicy).toEqual({
      minSupportedVersion: "1.2.0",
      recommendedVersion: "1.3.0",
      latestVersion: "1.3.1",
      iosStoreUrl: "https://apps.apple.com/app/quickex",
      androidStoreUrl: "market://details?id=com.pulsefy.quickex",
      releaseNotes: ["Security fixes", "Contract registry compatibility"],
    });
    expect(config.generatedAt).toBeDefined();
    expect(config.etag).toMatch(/^W\/"runtime-config-/);
  });

  // ── Preview Environment ──────────────────────────────────────────────────

  it("includes preview metadata when preview scope is provided", async () => {
    mockFeatureFlagsService.getSnapshot!.mockResolvedValue({
      metadata: {
        source: "bootstrap",
        storeAvailable: false,
        flagCount: 1,
        sensitiveFlagCount: 0,
        timestamp: new Date().toISOString(),
        environment: "staging",
      },
      flags: [
        {
          key: "bulk_invoicing_v2",
          name: "Bulk Invoicing v2",
          description: "",
          enabled: true,
          killSwitch: false,
          rolloutPercentage: 100,
          environments: ["development", "test", "production"],
          updatedAt: new Date().toISOString(),
          updatedBy: "bootstrap",
        },
      ],
    });

    mockContractRegistryService.getRegistry!.mockResolvedValue({
      network: "testnet",
      authoritative: true,
      version: 1,
      etag: 'W/"contract-registry-testnet-1"',
      data: {},
    });

    Object.defineProperty(mockAppConfigService, "environmentName", {
      value: "staging",
      configurable: true,
    });
    Object.defineProperty(mockAppConfigService, "isStaging", {
      value: true,
      configurable: true,
    });
    Object.defineProperty(mockAppConfigService, "publicApiUrl", {
      value: "https://preview-api.quickex.to",
      configurable: true,
    });

    const futureDate = new Date(Date.now() + 3600000).toISOString();
    mockPreviewScopeService.getScope!.mockResolvedValue({
      id: "scope-uuid-1",
      scope_id: "pr-123",
      branch_name: "feature/new-ui",
      expires_at: futureDate,
      owner_public_key: "GABCDEF123",
      github_pr_url: "https://github.com/owner/repo/pull/123",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    const config = await service.getConfig("pr-123");

    expect(config.environment).toBe("staging");
    expect(config.apiUrl).toBe("https://preview-api.quickex.to");
    expect(config.preview).toBeDefined();
    expect(config.preview!.scopeId).toBe("pr-123");
    expect(config.preview!.branchName).toBe("feature/new-ui");
    expect(config.preview!.valid).toBe(true);
    expect(config.preview!.expiresAt).toBe(futureDate);

    expect(config.etag).toMatch(/^W\/"runtime-config-/);
  });

  // ── Minimal / Fallback Environment ───────────────────────────────────────

  it("returns minimal config with fallbacks when services are unavailable", async () => {
    mockFeatureFlagsService.getSnapshot!.mockRejectedValue(
      new Error("feature flag store offline"),
    );
    mockContractRegistryService.getRegistry!.mockRejectedValue(
      new Error("contract registry offline"),
    );

    const config = await service.getConfig();

    expect(config.network.network).toBe("testnet");
    expect(config.contracts).toEqual({});
    expect(config.featureFlags).toEqual([]);
    expect(config.preview).toBeUndefined();
    expect(config.etag).toBeDefined();
  });

  it("returns minimal config with all field defaults when stellar config is missing", async () => {
    mockConfigService.get!.mockReturnValue(undefined);
    mockFeatureFlagsService.getSnapshot!.mockRejectedValue(
      new Error("offline"),
    );
    mockContractRegistryService.getRegistry!.mockRejectedValue(
      new Error("offline"),
    );

    const config = await service.getConfig();

    expect(config.network.network).toBe("testnet");
    expect(config.network.networkPassphrase).toBe(
      "Test SDF Network ; September 2015",
    );
    expect(config.network.horizonUrl).toBe(
      "https://horizon-testnet.stellar.org",
    );
    expect(config.network.sorobanRpcUrl).toBe(
      "https://soroban-testnet.stellar.org",
    );
    expect(config.contracts).toEqual({});
    expect(config.featureFlags).toEqual([]);
  });

  // ── Sensitive Value Exclusion ────────────────────────────────────────────

  it("does not expose sensitive fields like secret keys or API keys", async () => {
    mockFeatureFlagsService.getSnapshot!.mockResolvedValue({
      metadata: {
        source: "bootstrap",
        storeAvailable: false,
        flagCount: 0,
        sensitiveFlagCount: 0,
        timestamp: new Date().toISOString(),
      },
      flags: [],
    });

    mockContractRegistryService.getRegistry!.mockResolvedValue({
      network: "testnet",
      authoritative: true,
      version: 1,
      etag: 'W/"contract-registry-testnet-1"',
      data: {},
    });

    const config = await service.getConfig();

    const serialized = JSON.stringify(config);
    expect(serialized).not.toContain("secret");
    expect(serialized).not.toContain("api_key");
    expect(serialized).not.toContain("api-key");
    expect(serialized).not.toContain("private_key");
    expect(serialized).not.toContain("SENDGRID");
    expect(serialized).not.toContain("SUPABASE_SERVICE_ROLE");
    expect(serialized).not.toContain("stellar_secret");
    expect(config).not.toHaveProperty("sentry");
    expect(config).not.toHaveProperty("database");
    expect(config).not.toHaveProperty("secrets");
  });

  // ── ETag Consistency ─────────────────────────────────────────────────────

  it("produces consistent ETags for identical config", async () => {
    mockFeatureFlagsService.getSnapshot!.mockResolvedValue({
      metadata: {
        source: "store",
        storeAvailable: true,
        flagCount: 1,
        sensitiveFlagCount: 0,
        timestamp: new Date().toISOString(),
      },
      flags: [
        {
          key: "test_flag",
          name: "Test Flag",
          description: "",
          enabled: true,
          killSwitch: false,
          rolloutPercentage: 100,
          environments: ["test"],
          updatedAt: new Date().toISOString(),
          updatedBy: "bootstrap",
        },
      ],
    });

    mockContractRegistryService.getRegistry!.mockResolvedValue({
      network: "testnet",
      authoritative: true,
      version: 1,
      etag: 'W/"contract-registry-testnet-1"',
      data: {
        test_contract: {
          id: "CTEST123",
          wasmHash: "0xhash",
          version: 1,
          schemaVersion: "1.0.0",
          schemaCompatibility: { min: "1.0.0", max: "1.0.0" },
          networkPassphrase: "Test SDF Network ; September 2015",
          deploymentId: "deploy-001",
          initParams: {},
          metadata: {},
          updatedAt: new Date().toISOString(),
        },
      },
    });

    const configA = await service.getConfig();
    const configB = await service.getConfig();

    expect(configA.etag).toBe(configB.etag);
    expect(configA.network.network).toBe(configB.network.network);
    expect(configA.contracts.test_contract.contractId).toBe(
      configB.contracts.test_contract.contractId,
    );
  });

  // ── Mainnet Environment ──────────────────────────────────────────────────

  it("returns mainnet config when network is mainnet", async () => {
    mockConfigService.get!.mockImplementation((key: string) => {
      if (key === "stellar") {
        return {
          network: "mainnet",
          networkPassphrase: "Public Global Stellar Network ; September 2015",
          horizonBaseUrl: "https://horizon.stellar.org",
          sorobanRpcUrl: "https://soroban-rpc.mainnet.stellar.gateway.fm",
          sorobanRpcUrls: ["https://soroban-rpc.mainnet.stellar.gateway.fm"],
          explorerUrl: "https://stellar.expert/explorer/public",
        };
      }
      return undefined;
    });

    Object.defineProperty(mockAppConfigService, "network", {
      value: "mainnet",
      configurable: true,
    });
    Object.defineProperty(mockAppConfigService, "isMainnet", {
      value: true,
      configurable: true,
    });
    Object.defineProperty(mockAppConfigService, "publicApiUrl", {
      value: "https://api.quickex.to",
      configurable: true,
    });

    mockFeatureFlagsService.getSnapshot!.mockResolvedValue({
      metadata: {
        source: "bootstrap",
        storeAvailable: false,
        flagCount: 1,
        sensitiveFlagCount: 0,
        timestamp: new Date().toISOString(),
      },
      flags: [
        {
          key: "mainnet.refunds",
          name: "Mainnet Refunds",
          description: "",
          enabled: false,
          killSwitch: false,
          rolloutPercentage: 0,
          environments: ["production"],
          updatedAt: new Date().toISOString(),
          updatedBy: "bootstrap",
        },
      ],
    });

    mockContractRegistryService.getRegistry!.mockResolvedValue({
      network: "mainnet",
      authoritative: true,
      version: 1,
      etag: 'W/"contract-registry-mainnet-1"',
      data: {},
    });

    const config = await service.getConfig();

    expect(config.network.network).toBe("mainnet");
    expect(config.network.networkPassphrase).toBe(
      "Public Global Stellar Network ; September 2015",
    );
    expect(config.network.horizonUrl).toBe("https://horizon.stellar.org");
    expect(config.network.sorobanRpcUrl).toContain("mainnet");
    expect(config.apiUrl).toBe("https://api.quickex.to");
  });

  // ── Preview Scope Not Found ──────────────────────────────────────────────

  it("omits preview metadata when scope does not exist", async () => {
    mockFeatureFlagsService.getSnapshot!.mockResolvedValue({
      metadata: {
        source: "bootstrap",
        storeAvailable: false,
        flagCount: 0,
        sensitiveFlagCount: 0,
        timestamp: new Date().toISOString(),
      },
      flags: [],
    });

    mockContractRegistryService.getRegistry!.mockResolvedValue({
      network: "testnet",
      authoritative: true,
      version: 1,
      etag: 'W/"contract-registry-testnet-1"',
      data: {},
    });

    mockPreviewScopeService.getScope!.mockResolvedValue(null);

    const config = await service.getConfig("non-existent-scope");

    expect(config.preview).toBeUndefined();
  });
});
