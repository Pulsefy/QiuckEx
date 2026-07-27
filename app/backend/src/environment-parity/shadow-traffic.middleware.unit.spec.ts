import { Test, TestingModule } from "@nestjs/testing";
import { ShadowTrafficMiddleware } from "./shadow-traffic.middleware";
import { AppConfigService } from "../config/app-config.service";
import { MetricsService } from "../metrics/metrics.service";
import { Request, Response } from "express";

describe("ShadowTrafficMiddleware", () => {
  let middleware: ShadowTrafficMiddleware;
  let mockConfigService: Partial<AppConfigService>;
  let mockMetricsService: Partial<MetricsService>;

  beforeEach(async () => {
    mockConfigService = {
      shadowTrafficEnabled: false,
      shadowTrafficSampleRate: 0.1,
      shadowTrafficEndpoints: "/api/links,/api/transactions",
      productionBaseUrl: "https://production.example.com",
    };

    mockMetricsService = {
      recordShadowTrafficRequest: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ShadowTrafficMiddleware,
        { provide: AppConfigService, useValue: mockConfigService },
        { provide: MetricsService, useValue: mockMetricsService },
      ],
    }).compile();

    middleware = module.get<ShadowTrafficMiddleware>(ShadowTrafficMiddleware);
  });

  it("should be defined", () => {
    expect(middleware).toBeDefined();
  });

  describe("use", () => {
    it("should call next() when shadow traffic is disabled", () => {
      const req = {
        method: "GET",
        path: "/api/links",
        originalUrl: "/api/links?page=1",
        headers: {},
      } as Request;
      const res = {} as Response;
      const next = jest.fn();

      middleware.use(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("should call next() for non-GET requests even when enabled", () => {
      Object.defineProperty(mockConfigService, "shadowTrafficEnabled", {
        value: true,
        writable: true,
      });

      const req = {
        method: "POST",
        path: "/api/links",
        originalUrl: "/api/links",
        headers: {},
        body: { data: "test" },
      } as Request;
      const res = {} as Response;
      const next = jest.fn();

      middleware.use(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(
        mockMetricsService.recordShadowTrafficRequest,
      ).not.toHaveBeenCalled();
    });

    it("should call next() for non-shadowed endpoints", () => {
      Object.defineProperty(mockConfigService, "shadowTrafficEnabled", {
        value: true,
        writable: true,
      });

      const req = {
        method: "GET",
        path: "/api/other",
        originalUrl: "/api/other",
        headers: {},
      } as Request;
      const res = {} as Response;
      const next = jest.fn();

      middleware.use(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("shouldShadowEndpoint", () => {
    it("should return true for shadowed endpoints", () => {
      const shouldShadowEndpoint = (
        middleware as unknown as {
          shouldShadowEndpoint: (path: string) => boolean;
        }
      ).shouldShadowEndpoint.bind(middleware);
      const result = shouldShadowEndpoint("/api/links");
      expect(result).toBe(true);
    });

    it("should return false for non-shadowed endpoints", () => {
      const shouldShadowEndpoint = (
        middleware as unknown as {
          shouldShadowEndpoint: (path: string) => boolean;
        }
      ).shouldShadowEndpoint.bind(middleware);
      const result = shouldShadowEndpoint("/api/other");
      expect(result).toBe(false);
    });

    it("should match endpoint prefixes", () => {
      const shouldShadowEndpoint = (
        middleware as unknown as {
          shouldShadowEndpoint: (path: string) => boolean;
        }
      ).shouldShadowEndpoint.bind(middleware);
      const result = shouldShadowEndpoint("/api/links/123");
      expect(result).toBe(true);
    });
  });

  describe("shouldSample", () => {
    it("should return true when random value is less than sample rate", () => {
      Object.defineProperty(mockConfigService, "shadowTrafficSampleRate", {
        value: 1.0, // 100% sampling
        writable: true,
      });

      // Reinitialize middleware with updated config
      middleware = new ShadowTrafficMiddleware(
        mockConfigService as AppConfigService,
        mockMetricsService as MetricsService,
      );

      const shouldSample = (
        middleware as unknown as { shouldSample: () => boolean }
      ).shouldSample.bind(middleware);
      const result = shouldSample();
      expect(result).toBe(true);
    });

    it("should return false when random value is greater than sample rate", () => {
      Object.defineProperty(mockConfigService, "shadowTrafficSampleRate", {
        value: 0.0, // 0% sampling
        writable: true,
      });

      // Reinitialize middleware with updated config
      middleware = new ShadowTrafficMiddleware(
        mockConfigService as AppConfigService,
        mockMetricsService as MetricsService,
      );

      const shouldSample = (
        middleware as unknown as { shouldSample: () => boolean }
      ).shouldSample.bind(middleware);
      const result = shouldSample();
      expect(result).toBe(false);
    });
  });

  describe("sanitiseHeaders", () => {
    it("should remove sensitive headers", () => {
      const headers = {
        "content-type": "application/json",
        authorization: "Bearer secret-token",
        "x-api-key": "secret-key",
        cookie: "session=abc123",
      };

      const sanitiseHeaders = (
        middleware as unknown as {
          sanitiseHeaders: (
            headers: Request["headers"],
          ) => Record<string, string>;
        }
      ).sanitiseHeaders;
      const sanitized = sanitiseHeaders(headers);

      expect(sanitized["content-type"]).toBe("application/json");
      expect(sanitized["authorization"]).toBeUndefined();
      expect(sanitized["x-api-key"]).toBeUndefined();
      expect(sanitized["cookie"]).toBeUndefined();
      expect(sanitized["X-Shadow-Traffic"]).toBe("true");
    });

    it("should keep safe headers", () => {
      const headers = {
        "content-type": "application/json",
        "user-agent": "TestClient/1.0",
        accept: "application/json",
      };

      const sanitiseHeaders = (
        middleware as unknown as {
          sanitiseHeaders: (
            headers: Request["headers"],
          ) => Record<string, string>;
        }
      ).sanitiseHeaders;
      const sanitized = sanitiseHeaders(headers);

      expect(sanitized["content-type"]).toBe("application/json");
      expect(sanitized["user-agent"]).toBe("TestClient/1.0");
      expect(sanitized["accept"]).toBe("application/json");
    });

    it("should handle array headers", () => {
      const headers = {
        accept: ["application/json", "text/plain"],
      };

      const sanitiseHeaders = (
        middleware as unknown as {
          sanitiseHeaders: (
            headers: Request["headers"],
          ) => Record<string, string>;
        }
      ).sanitiseHeaders;
      const sanitized = sanitiseHeaders(headers);

      expect(sanitized["accept"]).toBe("application/json,text/plain");
    });
  });
});
