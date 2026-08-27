import { Test, TestingModule } from "@nestjs/testing";
import { PaymentsService } from "./payments.service";
import { HorizonService } from "../transactions/horizon.service";

describe("PaymentsService", () => {
  let service: PaymentsService;
  let horizonService: jest.Mocked<HorizonService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PaymentsService,
        {
          provide: HorizonService,
          useValue: {
            getPayments: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<PaymentsService>(PaymentsService);
    horizonService = module.get(HorizonService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("getRecentPayments()", () => {
    const mockPayments = {
      items: [
        {
          amount: "50.0000000",
          asset: "XLM",
          memo: "Invoice 1",
          timestamp: "2026-06-01T12:00:00Z",
          txHash: "tx_aaa",
          source: "GSOURCE1",
          destination: "GDEST1",
          status: "Success" as const,
          pagingToken: "tok1",
        },
        {
          amount: "100.0000000",
          asset: "XLM",
          memo: "Invoice 2",
          timestamp: "2026-06-15T10:00:00Z",
          txHash: "tx_bbb",
          source: "GSOURCE2",
          destination: "GDEST1",
          status: "Success" as const,
          pagingToken: "tok2",
        },
        {
          amount: "25.0000000",
          asset: "USDC",
          memo: null,
          timestamp: "2026-07-01T08:00:00Z",
          txHash: "tx_ccc",
          source: "GSOURCE3",
          destination: "GDEST1",
          status: "Success" as const,
          pagingToken: "tok3",
        },
      ],
      nextCursor: "tok3",
    };

    it("should return empty items when address is not provided", async () => {
      const result = await service.getRecentPayments({ address: "" });
      expect(result).toEqual({ items: [] });
      expect(horizonService.getPayments).not.toHaveBeenCalled();
    });

    it("should return all payments when no since filter is given", async () => {
      horizonService.getPayments.mockResolvedValue(mockPayments);

      const result = await service.getRecentPayments({
        address: "GDEST1",
        limit: 20,
      });

      expect(result.items).toHaveLength(3);
      expect(horizonService.getPayments).toHaveBeenCalledWith(
        "GDEST1",
        undefined,
        20,
      );
    });

    it("should filter payments by ISO since timestamp", async () => {
      horizonService.getPayments.mockResolvedValue(mockPayments);

      const result = await service.getRecentPayments({
        address: "GDEST1",
        since: "2026-06-10T00:00:00Z",
        limit: 20,
      });

      expect(result.items).toHaveLength(2);
      expect(result.items[0].txHash).toBe("tx_bbb");
      expect(result.items[1].txHash).toBe("tx_ccc");
    });

    it("should filter payments by epoch-ms since timestamp", async () => {
      horizonService.getPayments.mockResolvedValue(mockPayments);

      const sinceMs = new Date("2026-06-10T00:00:00Z").getTime().toString();

      const result = await service.getRecentPayments({
        address: "GDEST1",
        since: sinceMs,
        limit: 20,
      });

      expect(result.items).toHaveLength(2);
    });

    it("should default limit to 20 when not specified", async () => {
      horizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      await service.getRecentPayments({ address: "GDEST1" });

      expect(horizonService.getPayments).toHaveBeenCalledWith(
        "GDEST1",
        undefined,
        20,
      );
    });

    it("should return empty items when horizon returns no results", async () => {
      horizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const result = await service.getRecentPayments({ address: "GDEST1" });
      expect(result.items).toHaveLength(0);
    });

    it("should handle invalid since value gracefully (return all)", async () => {
      horizonService.getPayments.mockResolvedValue(mockPayments);

      const result = await service.getRecentPayments({
        address: "GDEST1",
        since: "not-a-date",
        limit: 20,
      });

      expect(result.items).toHaveLength(3);
    });

    it("should propagate HorizonService errors", async () => {
      horizonService.getPayments.mockRejectedValue(
        new Error("Horizon unavailable"),
      );

      await expect(
        service.getRecentPayments({ address: "GDEST1", limit: 20 }),
      ).rejects.toThrow("Horizon unavailable");
    });
  });
});
