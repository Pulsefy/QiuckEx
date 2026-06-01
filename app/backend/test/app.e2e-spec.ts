import {
  BadRequestException,
  INestApplication,
  ValidationPipe,
} from "@nestjs/common";
import { Test } from "@nestjs/testing";
import * as request from "supertest";

import { GlobalHttpExceptionFilter } from "../src/common/filters/global-http-exception.filter";
import { AppConfigService } from "../src/config";

import { AppModule } from "../src/app.module";
import { UsernamesService } from "../src/usernames/usernames.service";
import { HealthService } from "../src/health/health.service";
import { mapValidationErrors } from "../src/common/utils/validation-error.mapper";
import { ApiKeyGuard } from "../src/auth/guards/api-key.guard";
import { CustomThrottlerGuard } from "../src/auth/guards/custom-throttler.guard";

describe("App endpoints", () => {
  let app: INestApplication;
  let healthService: jest.Mocked<HealthService>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ApiKeyGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .overrideProvider(CustomThrottlerGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .overrideProvider(UsernamesService)
      .useValue({
        create: jest.fn().mockResolvedValue({ ok: true }),
        listByPublicKey: jest.fn().mockResolvedValue([]),
      })
      .overrideProvider(HealthService)
      .useValue({
        getHealthStatus: jest.fn().mockResolvedValue({
          status: "ok",
          version: "0.1.0",
          uptime: 100,
        }),
        getReadinessStatus: jest.fn().mockResolvedValue({
          ready: true,
          checks: [
            {
              name: "supabase",
              status: "up",
              latency: "10ms",
              details: undefined,
            },
            {
              name: "environment",
              status: "up",
              details: ["All critical env variables loaded"],
              latency: undefined,
            },
          ],
        }),
        getPublicStatus: jest.fn().mockResolvedValue({
          status: "operational",
          network: "testnet",
          lastLedger: 12345678,
          timestamp: "2024-01-01T00:00:00.000Z",
          version: "0.1.0",
          components: [
            {
              name: "horizon",
              status: "operational",
              detail: "Network: testnet",
            },
            {
              name: "soroban_rpc",
              status: "operational",
            },
            {
              name: "ingestion",
              status: "operational",
            },
          ],
        }),
      })
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

    healthService = moduleRef.get(HealthService) as jest.Mocked<HealthService>;

    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  // -----------------------------
  // HEALTH TESTS
  // -----------------------------

  it("GET /health returns ok", async () => {
    await request(app.getHttpServer()).get("/health").expect(200).expect({
      status: "ok",
      version: "0.1.0",
      uptime: 100,
    });
  });

  it("GET /ready returns ok when healthy", async () => {
    await request(app.getHttpServer())
      .get("/ready")
      .expect(200)
      .expect({
        ready: true,
        checks: [
          { name: "supabase", status: "up", latency: "10ms" },
          {
            name: "environment",
            status: "up",
            details: ["All critical env variables loaded"],
          },
        ],
      });
  });

  it("GET /ready returns 503 when unhealthy", async () => {
    healthService.getReadinessStatus.mockResolvedValueOnce({
      ready: false,
      timestamp: new Date().toISOString(),
      checks: [
        {
          name: "supabase",
          status: "down",
          latency: undefined,
          details: undefined,
        },
        {
          name: "environment",
          status: "up",
          details: ["All critical env variables loaded"],
          latency: undefined,
        },
      ],
    });

    await request(app.getHttpServer())
      .get("/ready")
      .expect(503)
      .expect({
        ready: false,
        checks: [
          { name: "supabase", status: "down" },
          {
            name: "environment",
            status: "up",
            details: ["All critical env variables loaded"],
          },
        ],
      });
  });

  // -----------------------------
  // PUBLIC STATUS TESTS
  // -----------------------------

  it("GET /status returns operational status", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(response.body).toMatchObject({
      status: "operational",
      network: "testnet",
      lastLedger: expect.any(Number),
      timestamp: expect.any(String),
      version: expect.any(String),
      components: expect.any(Array),
    });

    // Verify response shape
    expect(response.body.components).toHaveLength(3);
    expect(response.body.components[0]).toHaveProperty("name");
    expect(response.body.components[0]).toHaveProperty("status");
  });

  it("GET /status includes caching headers", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(response.header["cache-control"]).toBeDefined();
    expect(response.header["etag"]).toBeDefined();
  });

  it("GET /status returns 304 when ETag matches", async () => {
    // First request to get ETag
    const firstResponse = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    const etag = firstResponse.header["etag"];

    // Second request with If-None-Match header
    await request(app.getHttpServer())
      .get("/status")
      .set("If-None-Match", etag)
      .expect(304);
  });

  it("GET /status does not expose sensitive operational details", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    // Ensure no sensitive fields are exposed
    expect(response.body).not.toHaveProperty("checks");
    expect(response.body).not.toHaveProperty("ready");
    expect(response.body).not.toHaveProperty("latency");
    expect(response.body).not.toHaveProperty("error");
    expect(response.body).not.toHaveProperty("details");
    expect(response.body).not.toHaveProperty("supabase");
    expect(response.body).not.toHaveProperty("queue");
    expect(response.body).not.toHaveProperty("migrations");
  });

  it("GET /status includes network information", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(response.body.network).toBeDefined();
    expect(["testnet", "mainnet", "futurenet", "unknown"]).toContain(
      response.body.network,
    );
  });

  it("GET /status includes last ledger sequence", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(response.body.lastLedger).toBeDefined();
    expect(typeof response.body.lastLedger).toBe("number");
    expect(response.body.lastLedger).toBeGreaterThanOrEqual(0);
  });

  it("GET /status includes timestamp for cache validation", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(response.body.timestamp).toBeDefined();
    // Verify it's a valid ISO timestamp
    expect(new Date(response.body.timestamp).toISOString()).toBeDefined();
  });

  it("GET /status includes version information", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(response.body.version).toBeDefined();
    expect(typeof response.body.version).toBe("string");
  });

  it("GET /status includes component status array", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    expect(Array.isArray(response.body.components)).toBe(true);
    expect(response.body.components.length).toBeGreaterThan(0);

    // Each component should have name and status
    response.body.components.forEach(
      (component: { name: string; status: string; detail?: string }) => {
        expect(component).toHaveProperty("name");
        expect(component).toHaveProperty("status");
        expect(["operational", "degraded", "down"]).toContain(component.status);
      },
    );
  });

  it("GET /status helps distinguish client errors from platform downtime", async () => {
    const response = await request(app.getHttpServer())
      .get("/status")
      .expect(200);

    // If status is operational but user experiences issues, it's likely a client error
    expect(response.body.status).toBe("operational");
    expect(response.body.network).toBe("testnet");
  });

  // -----------------------------
  // USERNAME TESTS
  // -----------------------------

  it("POST /username returns ok for valid payload", async () => {
    const validKey = "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWRABCDEFGHIJKL";

    await request(app.getHttpServer())
      .post("/username")
      .send({
        username: "alice_123",
        publicKey: validKey,
      })
      .expect(201)
      .expect({ ok: true });
  });

  it("POST /username returns 400 with error envelope for invalid payload", async () => {
    const response = await request(app.getHttpServer())
      .post("/username")
      .send({ username: "A" })
      .expect(400);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        code: expect.any(String),
        message: expect.any(String),
      },
    });
  });
});
