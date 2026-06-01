import { Test, TestingModule } from "@nestjs/testing";
import { AnalyticsService } from "./analytics.service";
import { SupabaseService } from "../supabase/supabase.service";
import { AnalyticsInterval } from "./dto/analytics-query.dto";
import { BadRequestException } from "@nestjs/common";

describe("AnalyticsService", () => {
  let service: AnalyticsService;

  const mockSupabaseService = {
    getClient: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalyticsService,
        {
          provide: SupabaseService,
          useValue: mockSupabaseService,
        },
      ],
    }).compile();

    service = module.get<AnalyticsService>(AnalyticsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("getAnalyticsReport", () => {
    it("should return analytics report for a valid date range", async () => {
      const mockSupabaseClient = {
        from: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        or: jest.fn().mockReturnThis(),
        gte: jest.fn().mockReturnThis(),
        lte: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        rpc: jest.fn().mockResolvedValue({ error: null, data: null }),
      };

      mockSupabaseClient.from.mockReturnThis();
      mockSupabaseClient.select.mockReturnThis();
      mockSupabaseClient.or.mockReturnThis();
      mockSupabaseClient.gte.mockReturnThis();
      mockSupabaseClient.lte.mockReturnThis();
      mockSupabaseClient.order.mockResolvedValue({
        data: [
          {
            created_at: "2026-04-15T10:00:00Z",
            sender_public_key: "test-account",
            receiver_public_key: "other-account",
            asset: "XLM",
            amount: 100,
            status: "completed",
          },
        ],
        error: null,
      });

      mockSupabaseService.getClient.mockReturnValue(mockSupabaseClient);

      const result = await service.getAnalyticsReport(
        "test-account",
        "2026-04-01T00:00:00Z",
        "2026-04-30T23:59:59Z",
        AnalyticsInterval.DAILY,
      );

      expect(result).toBeDefined();
      expect(result.summary).toBeDefined();
      expect(result.timeSeries).toBeDefined();
      expect(result.window).toBeDefined();
    });

    it("should handle empty transaction results", async () => {
      const mockSupabaseClient = {
        from: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        or: jest.fn().mockReturnThis(),
        gte: jest.fn().mockReturnThis(),
        lte: jest.fn().mockReturnThis(),
        order: jest.fn().mockResolvedValue({
          data: [],
          error: null,
        }),
        rpc: jest.fn().mockResolvedValue({ error: null, data: null }),
      };

      mockSupabaseClient.from.mockReturnThis();
      mockSupabaseClient.select.mockReturnThis();
      mockSupabaseClient.or.mockReturnThis();
      mockSupabaseClient.gte.mockReturnThis();
      mockSupabaseClient.lte.mockReturnThis();

      mockSupabaseService.getClient.mockReturnValue(mockSupabaseClient);

      const result = await service.getAnalyticsReport(
        "test-account",
        "2026-04-01T00:00:00Z",
        "2026-04-30T23:59:59Z",
      );

      expect(result.summary.totalTransactions).toBe(0);
      expect(result.summary.totalVolumeUsd).toBe(0);
      expect(result.summary.conversionRate).toBe(0);
    });

    it("should throw error for invalid date format", async () => {
      await expect(
        service.getAnalyticsReport(
          "test-account",
          "invalid-date",
          "2026-04-30T23:59:59Z",
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it("should throw error when start date is after end date", async () => {
      await expect(
        service.getAnalyticsReport(
          "test-account",
          "2026-04-30T23:59:59Z",
          "2026-04-01T00:00:00Z",
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
