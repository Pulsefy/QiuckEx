import { Test, TestingModule } from "@nestjs/testing";
import { EnvironmentParityService } from "./environment-parity.service";
import { AppConfigService } from "../config/app-config.service";
import { MetricsService } from "../metrics/metrics.service";

describe("EnvironmentParityService", () => {
  let service: EnvironmentParityService;
  let mockConfigService: Partial<AppConfigService>;
  let mockMetricsService: Partial<MetricsService>;

  beforeEach(async () => {
    mockConfigService = {
      envParityCheckEnabled: false,
      environmentName: "test",
      network: "testnet",
      isProduction: false,
      isStaging: false,
      productionBaseUrl: undefined,
      stellarSecretKey: undefined,
      supabaseUrl: "https://test.supabase.co",
      supabaseAnonKey: "test-key",
    };

    mockMetricsService = {
      recordParityCheckResult: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EnvironmentParityService,
        { provide: AppConfigService, useValue: mockConfigService },
        { provide: MetricsService, useValue: mockMetricsService },
      ],
    }).compile();

    service = module.get<EnvironmentParityService>(EnvironmentParityService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("runParityChecks", () => {
    it("should run all parity checks and return results", async () => {
      const results = await service.runParityChecks();

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThan(0);
    });

    it("should record metrics for parity checks", async () => {
      await service.runParityChecks();

      expect(mockMetricsService.recordParityCheckResult).toHaveBeenCalledWith(
        "total",
        expect.any(Number),
        expect.any(Number),
        expect.any(Number),
      );
    });

    it("should include environment name check", async () => {
      const results = await service.runParityChecks();
      const envCheck = results.find((r) => r.check === "environment_name");

      expect(envCheck).toBeDefined();
      expect(envCheck?.status).toBe("pass");
    });

    it("should include network configuration check", async () => {
      const results = await service.runParityChecks();
      const networkCheck = results.find(
        (r) => r.check === "network_configuration",
      );

      expect(networkCheck).toBeDefined();
      expect(networkCheck?.status).toBe("pass");
    });

    it("should include supabase configuration check", async () => {
      const results = await service.runParityChecks();
      const supabaseCheck = results.find(
        (r) => r.check === "supabase_configuration",
      );

      expect(supabaseCheck).toBeDefined();
      expect(supabaseCheck?.status).toBe("pass");
    });
  });

  describe("getResults", () => {
    it("should return empty array before checks are run", () => {
      const results = service.getResults();
      expect(results).toEqual([]);
    });

    it("should return results after checks are run", async () => {
      await service.runParityChecks();
      const results = service.getResults();

      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe("onModuleInit", () => {
    it("should not run checks if envParityCheckEnabled is false", async () => {
      const spy = jest.spyOn(service, "runParityChecks");
      await service.onModuleInit();

      expect(spy).not.toHaveBeenCalled();
    });

    it("should run checks if envParityCheckEnabled is true", async () => {
      Object.defineProperty(mockConfigService, "envParityCheckEnabled", {
        value: true,
        writable: true,
      });
      const spy = jest.spyOn(service, "runParityChecks");
      await service.onModuleInit();

      expect(spy).toHaveBeenCalled();
    });
  });
});
