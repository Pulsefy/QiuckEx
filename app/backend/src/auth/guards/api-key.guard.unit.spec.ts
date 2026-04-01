import { ExecutionContext, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ApiKeyGuard } from "./api-key.guard";
import { ApiKeysService } from "src/api-keys/api-keys.service";
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
  } as unknown as ExecutionContext;

  return { ctx, req };
}

describe("ApiKeyGuard", () => {
  let guard: ApiKeyGuard;

  const mockApiKeysService = {
    validateApiKey: jest.fn(),
  };

  const mockReflector = {
    get: jest.fn(),
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
    mockApiKeysService.validateApiKey.mockResolvedValue(true);

    const { ctx, req } = makeContext({
      "x-api-key": "valid-key",
    });

    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(req.apiKey).toBeDefined();
  });

  it("should deny access when API key is invalid", async () => {
    mockApiKeysService.validateApiKey.mockResolvedValue(false);

    const { ctx } = makeContext({
      "x-api-key": "invalid-key",
    });

    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });
});