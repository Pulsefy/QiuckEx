import { Test, TestingModule } from "@nestjs/testing";
import { PaymentsController } from "./payments.controller";
import { PaymentsService } from "./payments.service";

describe("PaymentsController", () => {
  let controller: PaymentsController;
  let paymentsService: jest.Mocked<PaymentsService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PaymentsController],
      providers: [
        {
          provide: PaymentsService,
          useValue: {
            getRecentPayments: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<PaymentsController>(PaymentsController);
    paymentsService = module.get(PaymentsService);
  });

  it("should be defined", () => {
    expect(controller).toBeDefined();
  });

  describe("recent()", () => {
    const mockResult = {
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
      ],
    };

    it("should delegate to PaymentsService.getRecentPayments", async () => {
      paymentsService.getRecentPayments.mockResolvedValue(mockResult);

      const result = await controller.recent({
        address: "GDEST1",
        since: "2026-06-01T00:00:00Z",
        limit: 10,
      });

      expect(paymentsService.getRecentPayments).toHaveBeenCalledWith({
        address: "GDEST1",
        since: "2026-06-01T00:00:00Z",
        limit: 10,
      });
      expect(result).toEqual(mockResult);
    });

    it("should pass undefined limit when not provided", async () => {
      paymentsService.getRecentPayments.mockResolvedValue({ items: [] });

      await controller.recent({ address: "GDEST1" });

      expect(paymentsService.getRecentPayments).toHaveBeenCalledWith({
        address: "GDEST1",
        since: undefined,
        limit: undefined,
      });
    });

    it("should convert limit string to number", async () => {
      paymentsService.getRecentPayments.mockResolvedValue({ items: [] });

      await controller.recent({ address: "GDEST1", limit: 50 });

      expect(paymentsService.getRecentPayments).toHaveBeenCalledWith({
        address: "GDEST1",
        since: undefined,
        limit: 50,
      });
    });
  });
});
