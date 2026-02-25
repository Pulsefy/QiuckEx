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

describe("App endpoints", () => {
  let app: INestApplication;
  let healthService: jest.Mocked<HealthService>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
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
