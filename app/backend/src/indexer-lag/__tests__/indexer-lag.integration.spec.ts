import { Test, TestingModule } from "@nestjs/testing";
import { INestApplication, Controller, Get, UseGuards } from "@nestjs/common";
import request from "supertest";
import { IndexerLagModule } from "../indexer-lag.module";
import { RequiresIndexerLagCheck } from "../requires-indexer-lag-check.decorator";
import { IndexerLagService } from "../indexer-lag.service";
import { MetricsService } from "../../metrics/metrics.service";
import { AuditService } from "../../audit/audit.service";
import { AppConfigService } from "../../config";
import { IndexerCheckpointRepository } from "../../ingestion/indexer-checkpoint.repository";

@Controller("test-lag")
class TestLagController {
  @Get("protected")
  @RequiresIndexerLagCheck()
  getProtected() {
    return { success: true };
  }

  @Get("unprotected")
  getUnprotected() {
    return { success: true };
  }
}

describe("IndexerLagGuard Integration", () => {
  let app: INestApplication;
  let indexerLagService: IndexerLagService;
  let metricsService: MetricsService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [IndexerLagModule],
      controllers: [TestLagController],
      providers: [
        {
          provide: AppConfigService,
          useValue: {
            network: "testnet",
            indexerLagThresholdLedgers: 10,
            indexerLagGuardEnabled: true,
            indexerLagGuardOverride: false,
            quickexContractId: "CC123",
          },
        },
        {
          provide: IndexerCheckpointRepository,
          useValue: {
            getLastLedger: jest.fn().mockResolvedValue(100),
          },
        },
        {
          provide: AuditService,
          useValue: {
            log: jest.fn().mockResolvedValue(undefined),
          },
        },
        MetricsService,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    indexerLagService = moduleFixture.get<IndexerLagService>(IndexerLagService);
    metricsService = moduleFixture.get<MetricsService>(MetricsService);

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it("should allow unprotected route even when lagging", async () => {
    jest.spyOn(indexerLagService, "isBlocked").mockReturnValue(true);

    const res = await request(app.getHttpServer()).get("/test-lag/unprotected");
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it("should block protected route with 503 and Retry-After when lag exceeds threshold, and increment metric", async () => {
    jest.spyOn(indexerLagService, "isBlocked").mockReturnValue(true);

    const res = await request(app.getHttpServer()).get("/test-lag/protected");
    expect(res.status).toBe(503);
    expect(res.header["retry-after"]).toBe("60");
    expect(res.body.error).toBe("INDEXER_LAGGING");

    // Verify metric incremented
    const metricsOutput = await metricsService.getRegistry().metrics();
    expect(metricsOutput).toContain("indexer_lag_guard_blocked_requests_total");
  });

  it("should recover and allow protected route when lag drops below threshold", async () => {
    jest.spyOn(indexerLagService, "isBlocked").mockReturnValue(false);

    const res = await request(app.getHttpServer()).get("/test-lag/protected");
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});