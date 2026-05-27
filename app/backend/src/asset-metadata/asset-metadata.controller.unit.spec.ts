import { Test, TestingModule } from "@nestjs/testing";
import { AssetMetadataController } from "./asset-metadata.controller";
import { AssetMetadataService } from "./asset-metadata.service";
import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { Request, Response } from "express";
import * as crypto from "crypto";

describe("AssetMetadataController", () => {
  let controller: AssetMetadataController;
  let service: jest.Mocked<AssetMetadataService>;

  beforeEach(async () => {
    const mockService = {
      getAllAssetsMetadata: jest.fn(),
      getAssetMetadata: jest.fn(),
      refreshAssetMetadata: jest.fn(),
      verifyAsset: jest.fn(),
      getCacheStats: jest.fn(),
      clearCache: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AssetMetadataController],
      providers: [{ provide: AssetMetadataService, useValue: mockService }],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AssetMetadataController>(AssetMetadataController);
    service = module.get(AssetMetadataService);
  });

  describe("getAllAssets", () => {
    it("should return data and set ETag header on first request", async () => {
      const mockResult = {
        assets: [
          {
            code: "USDC",
            issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            type: "credit_alphanum4" as const,
            decimals: 7,
            verified: true,
            branding: {},
            isFallback: false,
            updatedAt: new Date().toISOString(),
          },
        ],
        total: 1,
      };

      service.getAllAssetsMetadata.mockResolvedValue(mockResult);

      const mockReq = { headers: {} } as unknown as Request;
      const headersMap: Record<string, string> = {};
      const mockRes = {
        setHeader: jest.fn().mockImplementation((name, val) => {
          headersMap[name] = val;
        }),
        status: jest.fn(),
      } as unknown as Response;

      const result = await controller.getAllAssets(mockReq, mockRes, "usdc");

      expect(service.getAllAssetsMetadata).toHaveBeenCalledWith("usdc");
      expect(result).toEqual(mockResult);
      expect(mockRes.setHeader).toHaveBeenCalledWith("Cache-Control", "public, max-age=0, must-revalidate");
      expect(headersMap["ETag"]).toBeDefined();
    });

    it("should return 304 Not Modified if If-None-Match matches ETag", async () => {
      const mockResult = { assets: [], total: 0 };
      service.getAllAssetsMetadata.mockResolvedValue(mockResult);

      const etag = `W/"${crypto
        .createHash("sha256")
        .update(JSON.stringify(mockResult))
        .digest("hex")}"`;

      const mockReq = {
        headers: { "if-none-match": etag },
      } as unknown as Request;

      const mockRes = {
        setHeader: jest.fn(),
        status: jest.fn(),
      } as unknown as Response;

      const result = await controller.getAllAssets(mockReq, mockRes);

      expect(result).toBeUndefined();
      expect(mockRes.status).toHaveBeenCalledWith(304);
    });
  });

  describe("verifyAsset", () => {
    it("should call service verifyAsset and return metadata", async () => {
      const body = {
        code: "USDC",
        issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        type: "credit_alphanum4" as const,
        decimals: 7,
        iconUrl: "https://example.com/icon.png",
        verified: true,
      };

      const expectedResponse = {
        code: "USDC",
        issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        type: "credit_alphanum4" as const,
        decimals: 7,
        verified: true,
        branding: {},
        isFallback: false,
        updatedAt: new Date().toISOString(),
      };

      service.verifyAsset.mockResolvedValue(expectedResponse);

      const result = await controller.verifyAsset(body);

      expect(service.verifyAsset).toHaveBeenCalledWith(
        "USDC",
        "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        true,
        {
          type: "credit_alphanum4",
          decimals: 7,
          iconUrl: "https://example.com/icon.png",
        }
      );
      expect(result).toEqual(expectedResponse);
    });
  });
});
