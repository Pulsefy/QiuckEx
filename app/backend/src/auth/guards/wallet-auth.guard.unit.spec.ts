import { ExecutionContext, ForbiddenException, UnauthorizedException } from "@nestjs/common";
import { Keypair } from "@stellar/stellar-sdk";
import { WalletAuthGuard } from "./wallet-auth.guard";
import { ApiKeysService } from "../../api-keys/api-keys.service";

describe("WalletAuthGuard", () => {
  let guard: WalletAuthGuard;
  let mockApiKeysService: jest.Mocked<ApiKeysService>;

  const walletA = Keypair.random();
  const walletB = Keypair.random();

  beforeEach(() => {
    mockApiKeysService = {
      validateKey: jest.fn(),
    } as unknown as jest.Mocked<ApiKeysService>;

    guard = new WalletAuthGuard(mockApiKeysService);
  });

  function makeContext(
    paramPublicKey?: string,
    headers: Record<string, string> = {},
    method = "GET",
    url = `/notifications/preferences/${paramPublicKey ?? ""}`,
  ): ExecutionContext {
    const request = {
      params: { publicKey: paramPublicKey },
      headers,
      method,
      originalUrl: url,
      url,
    };

    return {
      switchToHttp: () => ({
        getRequest: () => request,
      }),
    } as ExecutionContext;
  }

  function createSignature(
    keypair: Keypair,
    method: string,
    path: string,
    timestamp: string,
  ): string {
    const payload = `${method.toUpperCase()}:${path}:${timestamp}`;
    return keypair.sign(Buffer.from(payload)).toString("base64");
  }

  it("allows requests if endpoint has no publicKey parameter", async () => {
    const ctx = makeContext(undefined);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it("throws UnauthorizedException (401) when no auth headers are provided", async () => {
    const ctx = makeContext(walletA.publicKey());
    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it("allows self-access with valid Stellar signature", async () => {
    const timestamp = Date.now().toString();
    const signature = createSignature(
      walletA,
      "PUT",
      `/notifications/preferences/${walletA.publicKey()}`,
      timestamp,
    );

    const ctx = makeContext(
      walletA.publicKey(),
      {
        "x-signature": signature,
        "x-timestamp": timestamp,
      },
      "PUT",
      `/notifications/preferences/${walletA.publicKey()}`,
    );

    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it("throws UnauthorizedException (401) for invalid signature", async () => {
    const timestamp = Date.now().toString();
    const invalidSignature = Buffer.from("invalid-signature-data").toString("base64");

    const ctx = makeContext(
      walletA.publicKey(),
      {
        "x-signature": invalidSignature,
        "x-timestamp": timestamp,
      },
      "PUT",
      `/notifications/preferences/${walletA.publicKey()}`,
    );

    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it("throws UnauthorizedException (401) for stale timestamp (> 5 mins)", async () => {
    const staleTimestamp = (Date.now() - 10 * 60 * 1000).toString(); // 10 minutes ago
    const signature = createSignature(
      walletA,
      "PUT",
      `/notifications/preferences/${walletA.publicKey()}`,
      staleTimestamp,
    );

    const ctx = makeContext(
      walletA.publicKey(),
      {
        "x-signature": signature,
        "x-timestamp": staleTimestamp,
      },
      "PUT",
      `/notifications/preferences/${walletA.publicKey()}`,
    );

    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it("throws ForbiddenException (403) for cross-wallet update attempt", async () => {
    const timestamp = Date.now().toString();
    // Signature signed by Wallet A targeting Wallet B's endpoint
    const signature = createSignature(
      walletA,
      "PUT",
      `/notifications/preferences/${walletB.publicKey()}`,
      timestamp,
    );

    const ctx = makeContext(
      walletB.publicKey(), // Target is Wallet B
      {
        "x-signature": signature,
        "x-timestamp": timestamp,
        "x-public-key": walletA.publicKey(), // Authenticated as Wallet A
      },
      "PUT",
      `/notifications/preferences/${walletB.publicKey()}`,
    );

    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it("allows request with valid unscoped API key", async () => {
    mockApiKeysService.validateKey.mockResolvedValue({
      record: { id: "key-1", organization_id: "org-1" } as any,
      hasScope: () => true,
    });

    const ctx = makeContext(walletA.publicKey(), { "x-api-key": "valid-api-key" });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it("throws ForbiddenException (403) when API key is scoped to another wallet", async () => {
    mockApiKeysService.validateKey.mockResolvedValue({
      record: { id: "key-1", wallet_address: walletA.publicKey() } as any,
      hasScope: () => true,
    });

    const ctx = makeContext(walletB.publicKey(), { "x-api-key": "scoped-api-key" });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });
});
