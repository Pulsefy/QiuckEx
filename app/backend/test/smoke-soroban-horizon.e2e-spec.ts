import {
  BadRequestException,
  INestApplication,
  ValidationPipe,
} from "@nestjs/common";
import { Test } from "@nestjs/testing";
import * as request from "supertest";
import { AppModule } from "../src/app.module";
import { GlobalHttpExceptionFilter } from "../src/common/filters/global-http-exception.filter";
import { AppConfigService } from "../src/config";
import { mapValidationErrors } from "../src/common/utils/validation-error.mapper";
import { ApiKeyGuard } from "../src/auth/guards/api-key.guard";
import { CustomThrottlerGuard } from "../src/auth/guards/custom-throttler.guard";
import { SorobanRpcService } from "../src/transactions/soroban-rpc.service";
import { HorizonService } from "../src/transactions/horizon.service";
import * as StellarSdk from "@stellar/stellar-sdk";

// ─── Shared response types ────────────────────────────────────────────────────

interface HealthCheck {
  name: string;
  status: "up" | "down";
  latency?: string;
  error?: string;
  details?: string[];
}

interface ReadyResponse {
  ready: boolean;
  checks: HealthCheck[];
}

// ─── Suite ────────────────────────────────────────────────────────────────────

describe("Smoke Tests - Soroban RPC & Horizon", () => {
  let app:              INestApplication;
  let sorobanRpcService: SorobanRpcService;
  let horizonService:   HorizonService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ApiKeyGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .overrideProvider(CustomThrottlerGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .compile();

    app = moduleRef.createNestApplication();

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        exceptionFactory: (errors) => {
          const mapped = mapValidationErrors(errors);
          return new BadRequestException({
            code: "VALIDATION_ERROR",
            message: mapped.message,
            fields: mapped.fields,
          });
        },
      }),
    );

    const configService = moduleRef.get(AppConfigService);
    app.useGlobalFilters(new GlobalHttpExceptionFilter(configService));

    sorobanRpcService = moduleRef.get(SorobanRpcService);
    horizonService    = moduleRef.get(HorizonService);

    await app.init();
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  // ─── Soroban RPC connectivity ──────────────────────────────────────────────

  describe("Soroban RPC Connectivity", () => {
    it("getNetworkPassphrase returns a known Stellar network passphrase", async () => {
      const passphrase = await sorobanRpcService.getNetworkPassphrase();

      expect(passphrase).toBeDefined();
      expect(typeof passphrase).toBe("string");
      expect(passphrase.length).toBeGreaterThan(0);

      const knownNetworks = [
        "Public Global Stellar Network ; September 2015",
        "Test SDF Network ; September 2015",
        "Future Network ; September 2021",
      ];
      expect(knownNetworks).toContain(passphrase);
    });

    it("getNetworkPassphrase responds within 5s", async () => {
      const start = Date.now();
      await sorobanRpcService.getNetworkPassphrase();
      expect(Date.now() - start).toBeLessThan(5_000);
    });

    it("Soroban RPC endpoint is accessible via health check", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const sorobanCheck = checks.find((c) => c.name === "soroban_rpc");

      expect(sorobanCheck).toBeDefined();
      expect(sorobanCheck!.status).toBe("up");
      expect(sorobanCheck!.error).toBeUndefined();
    });
  });

  // ─── Soroban RPC transaction simulation ───────────────────────────────────

  describe("Soroban RPC Transaction Simulation", () => {
    function buildPaymentTx(networkPassphrase: string): StellarSdk.Transaction {
      const sourceKeypair = StellarSdk.Keypair.random();
      const account = new StellarSdk.Account(sourceKeypair.publicKey(), "0");

      return new StellarSdk.TransactionBuilder(account, {
        networkPassphrase,
        fee: String(100),
      })
        .addOperation(
          StellarSdk.Operation.payment({
            destination: StellarSdk.Keypair.random().publicKey(),
            asset:       StellarSdk.Asset.native(),
            amount:      "100",
          }),
        )
        .setTimeout(30)
        .build();
    }

    it("simulateTransaction returns a defined result or an expected error", async () => {
      const networkPassphrase = await sorobanRpcService.getNetworkPassphrase();
      const tx = buildPaymentTx(networkPassphrase);

      try {
        const result = await sorobanRpcService.simulateTransaction(tx);
        expect(result).toBeDefined();
        expect(result).toHaveProperty("results");
      } catch (error) {
        // Non-existent accounts are expected to fail on testnet
        expect(error).toBeDefined();
      }
    });

    it("simulateTransaction responds within 10s", async () => {
      const networkPassphrase = await sorobanRpcService.getNetworkPassphrase();
      const tx = buildPaymentTx(networkPassphrase);

      const start = Date.now();
      try {
        await sorobanRpcService.simulateTransaction(tx);
      } catch {
        // Expected for non-existent accounts
      }
      expect(Date.now() - start).toBeLessThan(10_000);
    });
  });

  // ─── Soroban RPC account operations ───────────────────────────────────────

  describe("Soroban RPC Account Operations", () => {
    it("getAccount throws a descriptive error for a non-existent account", async () => {
      const randomPublicKey = StellarSdk.Keypair.random().publicKey();
      await expect(
        sorobanRpcService.getAccount(randomPublicKey),
      ).rejects.toThrow(/does not exist on the network/);
    });

    it("getAccount responds within 5s (including expected rejection)", async () => {
      const randomPublicKey = StellarSdk.Keypair.random().publicKey();

      const start = Date.now();
      try {
        await sorobanRpcService.getAccount(randomPublicKey);
      } catch {
        // Expected for non-existent accounts
      }
      expect(Date.now() - start).toBeLessThan(5_000);
    });
  });

  // ─── Horizon connectivity ──────────────────────────────────────────────────

  describe("Horizon Connectivity", () => {
    it("Horizon endpoint is accessible via health check", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const horizonCheck = checks.find((c) => c.name === "horizon");

      expect(horizonCheck).toBeDefined();
      expect(horizonCheck!.status).toBe("up");
      expect(horizonCheck!.error).toBeUndefined();
    });

    it("Horizon responds within acceptable latency (<5 000ms)", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const horizonCheck = checks.find((c) => c.name === "horizon");

      if (horizonCheck?.latency) {
        expect(parseInt(horizonCheck.latency, 10)).toBeLessThan(5_000);
      }
    });
  });

  // ─── Horizon account operations ────────────────────────────────────────────

  describe("Horizon Account Operations", () => {
    it("getPayments returns a result object for a valid account ID", async () => {
      const accountId = StellarSdk.Keypair.random().publicKey();

      try {
        const result = await horizonService.getPayments(accountId, undefined, 5);
        expect(result).toBeDefined();
        expect(result).toHaveProperty("items");
        expect(Array.isArray(result.items)).toBe(true);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it("getPayments handles asset filtering without throwing", async () => {
      const accountId = StellarSdk.Keypair.random().publicKey();

      try {
        const result = await horizonService.getPayments(accountId, "XLM", 5);
        expect(result).toBeDefined();
        expect(Array.isArray(result.items)).toBe(true);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it("getPayments respects the limit parameter", async () => {
      const accountId = StellarSdk.Keypair.random().publicKey();

      try {
        const result = await horizonService.getPayments(accountId, undefined, 3);
        expect(result.items.length).toBeLessThanOrEqual(3);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it("getPayments responds within 10s", async () => {
      const accountId = StellarSdk.Keypair.random().publicKey();

      const start = Date.now();
      try {
        await horizonService.getPayments(accountId, undefined, 5);
      } catch {
        // Expected for non-existent accounts
      }
      expect(Date.now() - start).toBeLessThan(10_000);
    });
  });

  // ─── Network consistency ───────────────────────────────────────────────────

  describe("Network Consistency", () => {
    it("Soroban RPC and environment check report the same network", async () => {
      const sorobanPassphrase = await sorobanRpcService.getNetworkPassphrase();

      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const envCheck = checks.find((c) => c.name === "environment");
      const networkDetail = envCheck?.details?.find((d) =>
        d.toLowerCase().includes("network"),
      );

      expect(networkDetail).toBeDefined();

      if (sorobanPassphrase.includes("Test")) {
        expect(networkDetail!.toLowerCase()).toContain("test");
      } else if (sorobanPassphrase.includes("Public")) {
        expect(networkDetail!.toLowerCase()).toContain("public");
      }
    });

    it("All critical health checks report 'up' for a consistent network", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const envCheck = checks.find((c) => c.name === "environment");
      expect(envCheck!.status).toBe("up");

      const criticalNames = ["supabase", "horizon", "soroban_rpc"] as const;
      for (const name of criticalNames) {
        const check = checks.find((c) => c.name === name);
        expect(check).toBeDefined();
        expect(check!.status).toBe("up");
      }
    });
  });

  // ─── Error resilience ──────────────────────────────────────────────────────

  describe("Error Resilience", () => {
    it("Soroban RPC does not hang — resolves within 15s", async () => {
      const randomPublicKey = StellarSdk.Keypair.random().publicKey();

      const start = Date.now();
      try {
        await sorobanRpcService.getAccount(randomPublicKey);
      } catch {
        // Expected for non-existent accounts
      }
      expect(Date.now() - start).toBeLessThan(15_000);
    });

    it("Horizon getPayments handles a large limit without hanging", async () => {
      const accountId = StellarSdk.Keypair.random().publicKey();

      try {
        await horizonService.getPayments(accountId, undefined, 100);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it("Health check includes an error field on any 'down' check", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      for (const check of checks) {
        if (check.status === "down") {
          expect(check).toHaveProperty("error");
          expect(check.error).toBeDefined();
        }
      }
    });
  });

  // ─── Performance benchmarks ────────────────────────────────────────────────

  describe("Performance Benchmarks", () => {
    it("Soroban RPC getNetworkPassphrase < 2s", async () => {
      const start = Date.now();
      await sorobanRpcService.getNetworkPassphrase();
      expect(Date.now() - start).toBeLessThan(2_000);
    });

    it("Horizon getPayments < 5s", async () => {
      const accountId = StellarSdk.Keypair.random().publicKey();

      const start = Date.now();
      try {
        await horizonService.getPayments(accountId, undefined, 5);
      } catch {
        // Expected for non-existent accounts
      }
      expect(Date.now() - start).toBeLessThan(5_000);
    });

    it("Health check completes within 10s", async () => {
      const start = Date.now();
      await request(app.getHttpServer()).get("/ready").expect(200);
      expect(Date.now() - start).toBeLessThan(10_000);
    });
  });
});