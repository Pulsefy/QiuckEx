import { Test, TestingModule } from "@nestjs/testing";
import { AssetMetadataService } from "./asset-metadata.service";
import { AssetMetadataCache } from "./cache/asset-metadata.cache";
import { TomlFetcherService } from "./toml-fetcher.service";
import { HorizonService } from "../stellar/horizon.service";
import { SupabaseService } from "../supabase/supabase.service";
import { VERIFIED_STELLAR_ASSETS } from "../stellar/verified-assets.constant";

describe("AssetMetadataService", () => {
  let service: AssetMetadataService;
  let cache: jest.Mocked<AssetMetadataCache>;
  let tomlFetcher: jest.Mocked<TomlFetcherService>;
  let supabaseService: jest.Mocked<SupabaseService>;

  const mockDbAssets = [
    {
      id: "uuid-1",
      code: "USDC",
      issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      type: "credit_alphanum4" as const,
      decimals: 7,
      icon_url: "https://example.com/usdc.png",
      verified: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: "uuid-2",
      code: "XLM",
      issuer: null,
      type: "native" as const,
      decimals: 7,
      icon_url: "https://example.com/xlm.png",
      verified: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  beforeEach(async () => {
    const mockCache = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn(),
      clear: jest.fn(),
      getStats: jest.fn(),
    };

    const mockTomlFetcher = {
      fetchStellarToml: jest.fn(),
      findCurrency: jest.fn(),
      extractBranding: jest.fn(),
    };

    const mockHorizonService = {
      // Mock any horizon methods used
    };

    const mockSupabaseService = {
      fetchVerifiedAssets: jest.fn(),
      searchVerifiedAssets: jest.fn(),
      upsertVerifiedAsset: jest.fn(),
      updateAssetVerificationStatus: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AssetMetadataService,
        { provide: AssetMetadataCache, useValue: mockCache },
        { provide: TomlFetcherService, useValue: mockTomlFetcher },
        { provide: HorizonService, useValue: mockHorizonService },
        { provide: SupabaseService, useValue: mockSupabaseService },
      ],
    }).compile();

    service = module.get<AssetMetadataService>(AssetMetadataService);
    cache = module.get(AssetMetadataCache);
    tomlFetcher = module.get(TomlFetcherService);
    supabaseService = module.get(SupabaseService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("getAllAssetsMetadata", () => {
    it("should return verified assets from database if database fetch succeeds", async () => {
      supabaseService.fetchVerifiedAssets.mockResolvedValue(mockDbAssets);
      cache.get.mockReturnValue(undefined); // cache miss
      tomlFetcher.fetchStellarToml.mockResolvedValue({});

      const result = await service.getAllAssetsMetadata();

      expect(supabaseService.fetchVerifiedAssets).toHaveBeenCalled();
      expect(result.assets.length).toBe(2);
      expect(result.assets[0].code).toBe("USDC");
      expect(result.assets[1].code).toBe("XLM");
      expect(cache.set).toHaveBeenCalled();
    });

    it("should fall back to constant verified assets list if database returns empty or fails", async () => {
      supabaseService.fetchVerifiedAssets.mockRejectedValue(new Error("DB error"));
      cache.get.mockReturnValue(undefined);
      tomlFetcher.fetchStellarToml.mockResolvedValue({});

      const result = await service.getAllAssetsMetadata();

      expect(supabaseService.fetchVerifiedAssets).toHaveBeenCalled();
      expect(result.assets.length).toBe(VERIFIED_STELLAR_ASSETS.length);
      expect(result.assets.map(a => a.code)).toContain("XLM");
      expect(result.assets.map(a => a.code)).toContain("USDC");
    });

    it("should return cached assets list if list is cached", async () => {
      const mockCachedResponse = { assets: [], total: 0 };
      cache.get.mockReturnValue(mockCachedResponse);

      const result = await service.getAllAssetsMetadata();

      expect(cache.get).toHaveBeenCalledWith("list:all");
      expect(supabaseService.fetchVerifiedAssets).not.toHaveBeenCalled();
      expect(result).toEqual(mockCachedResponse);
    });

    it("should filter assets by search query", async () => {
      supabaseService.searchVerifiedAssets.mockResolvedValue([mockDbAssets[0]]); // only USDC
      cache.get.mockReturnValue(undefined);
      tomlFetcher.fetchStellarToml.mockResolvedValue({});

      const result = await service.getAllAssetsMetadata("usdc");

      expect(supabaseService.searchVerifiedAssets).toHaveBeenCalledWith("usdc");
      expect(result.assets.length).toBe(1);
      expect(result.assets[0].code).toBe("USDC");
    });
  });

  describe("getAssetMetadata", () => {
    it("should return cached asset metadata if it is cached", async () => {
      const mockCachedAsset = {
        asset: { code: "USDC", issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" },
        branding: { name: "USD Coin" },
        isFallback: false,
      };
      cache.get.mockReturnValue(mockCachedAsset);

      const result = await service.getAssetMetadata("USDC", "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN");

      expect(cache.get).toHaveBeenCalledWith("USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN");
      expect(result.code).toBe("USDC");
      expect(result.branding.name).toBe("USD Coin");
    });
  });

  describe("verifyAsset", () => {
    it("should upsert asset to database, clear cache and return metadata", async () => {
      const updatedAsset = {
        id: "uuid-3",
        code: "NEWCOIN",
        issuer: "GBNEWCOIN",
        type: "credit_alphanum12" as const,
        decimals: 7,
        icon_url: "https://example.com/icon.png",
        verified: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      supabaseService.upsertVerifiedAsset.mockResolvedValue(updatedAsset);
      supabaseService.fetchVerifiedAssets.mockResolvedValue([updatedAsset]);
      tomlFetcher.fetchStellarToml.mockResolvedValue({});

      const result = await service.verifyAsset(
        "NEWCOIN",
        "GBNEWCOIN",
        true,
        {
          type: "credit_alphanum12",
          decimals: 7,
          iconUrl: "https://example.com/icon.png",
        }
      );

      expect(supabaseService.upsertVerifiedAsset).toHaveBeenCalledWith({
        code: "NEWCOIN",
        issuer: "GBNEWCOIN",
        type: "credit_alphanum12",
        decimals: 7,
        icon_url: "https://example.com/icon.png",
        verified: true,
      });
      expect(cache.clear).toHaveBeenCalled();
      expect(result.code).toBe("NEWCOIN");
    });
  });
});
