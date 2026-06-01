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

describe("Smoke Tests - Deployment Validation", () => {
  let app: INestApplication;

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

    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  // ─── Health endpoints ──────────────────────────────────────────────────────

  describe("Health Endpoints", () => {
    it("GET /health returns 200 with basic health status", async () => {
      const response = await request(app.getHttpServer())
        .get("/health")
        .expect(200);

      expect(response.body).toHaveProperty("status");
      expect(response.body).toHaveProperty("version");
      expect(response.body).toHaveProperty("uptime");
      expect(response.body.status).toBe("ok");
    });

    it("GET /ready returns 200 when all dependencies are healthy", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const body = response.body as ReadyResponse;
      expect(body).toHaveProperty("ready");
      expect(body).toHaveProperty("checks");
      expect(body.ready).toBe(true);

      const checkNames = body.checks.map((c) => c.name);
      expect(checkNames).toContain("supabase");
      expect(checkNames).toContain("environment");
      expect(checkNames).toContain("horizon");
      expect(checkNames).toContain("soroban_rpc");
    });

    it("GET /ready includes latency metrics for external services", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const supabaseCheck = checks.find((c) => c.name === "supabase");
      const horizonCheck  = checks.find((c) => c.name === "horizon");
      const sorobanCheck  = checks.find((c) => c.name === "soroban_rpc");

      const hasLatency =
        supabaseCheck?.latency ||
        horizonCheck?.latency  ||
        sorobanCheck?.latency;

      expect(hasLatency).toBeDefined();
    });
  });

  // ─── Network configuration ─────────────────────────────────────────────────

  describe("Network Configuration", () => {
    it("environment check reports correct network", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const envCheck = checks.find((c) => c.name === "environment");

      expect(envCheck).toBeDefined();
      expect(envCheck!.status).toBe("up");

      const networkDetail = envCheck!.details?.find((d) =>
        d.toLowerCase().includes("network"),
      );
      expect(networkDetail).toBeDefined();
    });

    it("Horizon connectivity is functional", async () => {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);

      const { checks } = response.body as ReadyResponse;
      const horizonCheck = checks.find((c) => c.name === "horizon");

      expect(horizonCheck).toBeDefined();
      expect(horizonCheck!.status).toBe("up");
      expect(horizonCheck!.error).toBeUndefined();
    });

    it("Soroban RPC connectivity is functional", async () => {
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

  // ─── Link metadata ─────────────────────────────────────────────────────────

  describe("Link Metadata Endpoint", () => {
    it("POST /links/metadata generates valid metadata for XLM payment", async () => {
      const response = await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: 100, asset: "XLM", memo: "Smoke test payment" })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty("amount");
      expect(response.body.data).toHaveProperty("canonical");
      expect(response.body.data.amount).toBe("100.0000000");
      expect(response.body.data.asset).toBe("XLM");
    });

    it("POST /links/metadata handles privacy flag correctly", async () => {
      const response = await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: 50, privacy: true })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.privacy).toBe(true);
    });

    it("POST /links/metadata calculates expiration date when specified", async () => {
      const response = await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: 25, expirationDays: 30 })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty("expiresAt");

      const expiresAt = new Date(response.body.data.expiresAt as string);
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it("POST /links/metadata rejects invalid asset → 400", async () => {
      const response = await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: 10, asset: "INVALID_ASSET" })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toHaveProperty("code");
    });

    it("POST /links/metadata rejects negative amounts → 400", async () => {
      await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: -10 })
        .expect(400);
    });
  });

  // ─── Username endpoints ────────────────────────────────────────────────────

  describe("Username Endpoints", () => {
    it("GET /username/search returns results for valid query", async () => {
      const response = await request(app.getHttpServer())
        .get("/username/search")
        .query({ query: "alice", limit: 5 })
        .expect(200);

      expect(response.body).toHaveProperty("profiles");
      expect(response.body).toHaveProperty("total");
      expect(Array.isArray(response.body.profiles)).toBe(true);
    });

    it("GET /username/trending returns trending creators", async () => {
      const response = await request(app.getHttpServer())
        .get("/username/trending")
        .query({ timeWindowHours: 24, limit: 5 })
        .expect(200);

      expect(response.body).toHaveProperty("creators");
      expect(response.body).toHaveProperty("timeWindowHours");
      expect(response.body).toHaveProperty("calculatedAt");
      expect(Array.isArray(response.body.creators)).toBe(true);
    });

    it("GET /username/recently-active returns recently active users", async () => {
      const response = await request(app.getHttpServer())
        .get("/username/recently-active")
        .query({ timeWindowHours: 24, limit: 5 })
        .expect(200);

      expect(response.body).toHaveProperty("users");
      expect(response.body).toHaveProperty("timeWindowHours");
      expect(response.body).toHaveProperty("calculatedAt");
      expect(Array.isArray(response.body.users)).toBe(true);
    });

    it("GET /username/search rejects queries shorter than 2 characters → 400", async () => {
      await request(app.getHttpServer())
        .get("/username/search")
        .query({ query: "a", limit: 5 })
        .expect(400);
    });
  });

  // ─── Asset metadata ────────────────────────────────────────────────────────

  describe("Asset Metadata Endpoint", () => {
    it("GET /asset-metadata returns metadata for XLM", async () => {
      const response = await request(app.getHttpServer())
        .get("/asset-metadata")
        .query({ asset_code: "XLM" })
        .expect(200);

      expect(response.body).toHaveProperty("asset_code");
      expect(response.body.asset_code).toBe("XLM");
    });

    it("GET /asset-metadata returns 404 for unknown asset", async () => {
      await request(app.getHttpServer())
        .get("/asset-metadata")
        .query({ asset_code: "NONEXISTENT" })
        .expect(404);
    });
  });

  // ─── Critical dependencies ─────────────────────────────────────────────────

  describe("Critical Dependencies", () => {
    async function getChecks(): Promise<HealthCheck[]> {
      const response = await request(app.getHttpServer())
        .get("/ready")
        .expect(200);
      return (response.body as ReadyResponse).checks;
    }

    it("Supabase database is accessible", async () => {
      const checks = await getChecks();
      const supabaseCheck = checks.find((c) => c.name === "supabase");
      expect(supabaseCheck!.status).toBe("up");
      expect(supabaseCheck!.error).toBeUndefined();
    });

    it("Database migrations are applied", async () => {
      const checks = await getChecks();
      const migrationCheck = checks.find((c) => c.name === "migrations");
      expect(migrationCheck!.status).toBe("up");
      expect(migrationCheck!.error).toBeUndefined();
    });

    it("Job queue is operational", async () => {
      const checks = await getChecks();
      const queueCheck = checks.find((c) => c.name === "queue");
      expect(queueCheck!.status).toBe("up");
      expect(queueCheck!.error).toBeUndefined();
    });
  });

  // ─── Rate limiting ─────────────────────────────────────────────────────────

  describe("Rate Limiting", () => {
    it("Discovery endpoints exist and are reachable", async () => {
      await request(app.getHttpServer())
        .get("/username/search")
        .query({ query: "test", limit: 5 })
        .expect(200);

      await request(app.getHttpServer())
        .get("/username/trending")
        .query({ timeWindowHours: 24, limit: 5 })
        .expect(200);

      await request(app.getHttpServer())
        .get("/username/recently-active")
        .query({ timeWindowHours: 24, limit: 5 })
        .expect(200);
    });
  });

  // ─── Error handling ────────────────────────────────────────────────────────

  describe("Error Handling", () => {
    it("Returns 404 for non-existent endpoints", async () => {
      await request(app.getHttpServer())
        .get("/non-existent-endpoint")
        .expect(404);
    });

    it("Returns a proper error envelope for validation errors", async () => {
      const response = await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: "invalid" })
        .expect(400);

      expect(response.body).toHaveProperty("success");
      expect(response.body.success).toBe(false);
      expect(response.body).toHaveProperty("error");
    });
  });

  // ─── Performance benchmarks ────────────────────────────────────────────────

  describe("Performance Benchmarks", () => {
    it("Health endpoint responds within 100ms", async () => {
      const start = Date.now();
      await request(app.getHttpServer()).get("/health").expect(200);
      expect(Date.now() - start).toBeLessThan(100);
    });

    it("Link metadata generation responds within 500ms", async () => {
      const start = Date.now();
      await request(app.getHttpServer())
        .post("/links/metadata")
        .send({ amount: 100, asset: "XLM" })
        .expect(200);
      expect(Date.now() - start).toBeLessThan(500);
    });

    it("Username search responds within 1 000ms", async () => {
      const start = Date.now();
      await request(app.getHttpServer())
        .get("/username/search")
        .query({ query: "test", limit: 10 })
        .expect(200);
      expect(Date.now() - start).toBeLessThan(1_000);
    });
  });
});