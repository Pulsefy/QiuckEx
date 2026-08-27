import { ExecutionContext, ForbiddenException, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ApiKeyGuard } from "./api-key.guard";
import { ApiKeysService } from "../../api-keys/api-keys.service";
import { Test } from "@nestjs/testing";
import { Request } from "express";

/** Create a typed mock ExecutionContext with request + optional apiKey */
function makeContext(headers: Record<string, string> = {}) {
  const req = {
    headers,
  } as Request & { apiKey?: unknown };

  const ctx = {
    switchToHttp: () => ({
      getRequest: () => req,
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;

  return { ctx, req };
}

describe("ApiKeyGuard", () => {
  let guard: ApiKeyGuard;

  const mockApiKeysService = {
    validateKey: jest.fn(),
    isOverQuota: jest.fn().mockReturnValue(false),
  };

  const mockReflector = {
    getAllAndOverride: jest.fn().mockReturnValue([]),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module = await Test.createTestingModule({
      providers: [
        ApiKeyGuard,
        {
          provide: ApiKeysService,
          useValue: mockApiKeysService,
        },
        {
          provide: Reflector,
          useValue: mockReflector,
        },
      ],
    }).compile();

    guard = module.get<ApiKeyGuard>(ApiKeyGuard);
  });

  it("should allow public access when no API key is provided", async () => {
    const { ctx } = makeContext();

    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
  });

  it("should allow access when API key is valid", async () => {
    mockApiKeysService.validateKey.mockResolvedValue({
      record: {
        id: "api-key-id",
        name: "test key",
        scopes: [],
        request_count: 0,
        monthly_quota: 1000,
      },
      hasScope: () => true,
    });

    const { ctx, req } = makeContext({
      "x-api-key": "valid-key",
    });

    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(req.apiKey).toBeDefined();
  });

  it("should deny access when API key is invalid", async () => {
    mockApiKeysService.validateKey.mockResolvedValue(null);

    const { ctx } = makeContext({
      "x-api-key": "invalid-key",
    });

    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it("should deny access with INSUFFICIENT_SCOPE when API key is missing required scope", async () => {
    mockReflector.getAllAndOverride.mockReturnValue(["links:write"]);
    mockApiKeysService.validateKey.mockResolvedValue({
      record: {
        id: "api-key-id",
        name: "test key",
        scopes: ["links:read"],
        request_count: 0,
        monthly_quota: 1000,
      },
      hasScope: (s: string) => ["links:read"].includes(s),
    });

    const { ctx } = makeContext({
      "x-api-key": "valid-key",
    });

    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);

    try {
      await guard.canActivate(ctx);
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ForbiddenException);
      const res = (err as ForbiddenException).getResponse();
      expect(res).toEqual(
        expect.objectContaining({
          error: "INSUFFICIENT_SCOPE",
          message: expect.stringContaining("links:write"),
        }),
      );
    }
  });

  it("should allow access when API key has the required scope", async () => {
    mockReflector.getAllAndOverride.mockReturnValue(["links:write"]);
    mockApiKeysService.validateKey.mockResolvedValue({
      record: {
        id: "api-key-id",
        name: "test key",
        scopes: ["links:write", "links:read"],
        request_count: 0,
        monthly_quota: 1000,
      },
      hasScope: (s: string) => ["links:write", "links:read"].includes(s),
    });

    const { ctx, req } = makeContext({
      "x-api-key": "valid-key",
    });

    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(req.apiKey).toBeDefined();
  });

  it("should skip scope check when route has no @RequireScopes metadata", async () => {
    mockReflector.getAllAndOverride.mockReturnValue([]);
    const hasScopeMock = jest.fn().mockReturnValue(false);

    mockApiKeysService.validateKey.mockResolvedValue({
      record: {
        id: "api-key-id",
        name: "test key",
        scopes: [],
        request_count: 0,
        monthly_quota: 1000,
      },
      hasScope: hasScopeMock,
    });

    const { ctx } = makeContext({
      "x-api-key": "valid-key",
    });

    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(hasScopeMock).not.toHaveBeenCalled();
  });
});