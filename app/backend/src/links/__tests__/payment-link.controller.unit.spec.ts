import { Test, TestingModule } from "@nestjs/testing";
import { BadRequestException } from "@nestjs/common";
import { PaymentLinkController } from "../payment-link.controller";
import { PaymentLinkService } from "../payment-link.service";
import { LinkState } from "../link-state-machine";
import { CustomThrottlerGuard } from "../../auth/guards/custom-throttler.guard";

describe("PaymentLinkController", () => {
  let controller: PaymentLinkController;
  let service: jest.Mocked<PaymentLinkService>;

  const mockStatusResponse = {
    state: LinkState.ACTIVE,
    username: "testuser",
    amount: "100.0000000",
    asset: "XLM",
    memo: "Test payment",
    destinationPublicKey: "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    expiresAt: new Date(Date.now() + 86400000 * 30),
    transactionHash: null,
    paidAt: null,
    swapOptions: null,
    acceptsMultipleAssets: false,
    acceptedAssets: null,
    userMessage: "This payment link is active and ready to receive payment",
    availableActions: ["pay", "share"],
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PaymentLinkController],
      providers: [
        {
          provide: PaymentLinkService,
          useValue: {
            getPaymentLinkStatus: jest.fn(),
          },
        },
      ],
    })
      .overrideGuard(CustomThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<PaymentLinkController>(PaymentLinkController);
    service = module.get(PaymentLinkService);
  });

  it("should be defined", () => {
    expect(controller).toBeDefined();
  });

  describe("getPaymentLinkStatus()", () => {
    it("should return payment link status for valid params", async () => {
      service.getPaymentLinkStatus.mockResolvedValue(mockStatusResponse);

      const result = await controller.getPaymentLinkStatus(
        "testuser",
        "100",
        "XLM",
        "Test payment",
      );

      expect(result.state).toBe(LinkState.ACTIVE);
      expect(result.username).toBe("testuser");
      expect(service.getPaymentLinkStatus).toHaveBeenCalledWith({
        username: "testuser",
        amount: 100,
        asset: "XLM",
        memo: "Test payment",
        acceptedAssets: undefined,
      });
    });

    it("should throw BadRequestException when username is missing", async () => {
      await expect(controller.getPaymentLinkStatus("", "100")).rejects.toThrow(
        BadRequestException,
      );
    });

    it("should throw BadRequestException when amount is not a number", async () => {
      await expect(
        controller.getPaymentLinkStatus("testuser", "not-a-number"),
      ).rejects.toThrow(BadRequestException);
    });

    it("should throw BadRequestException when amount is zero", async () => {
      await expect(
        controller.getPaymentLinkStatus("testuser", "0"),
      ).rejects.toThrow(BadRequestException);
    });

    it("should throw BadRequestException when amount is negative", async () => {
      await expect(
        controller.getPaymentLinkStatus("testuser", "-50"),
      ).rejects.toThrow(BadRequestException);
    });

    it("should default asset to XLM when not provided", async () => {
      service.getPaymentLinkStatus.mockResolvedValue(mockStatusResponse);

      await controller.getPaymentLinkStatus("testuser", "100");

      expect(service.getPaymentLinkStatus).toHaveBeenCalledWith(
        expect.objectContaining({ asset: "XLM" }),
      );
    });

    it("should parse comma-separated acceptedAssets", async () => {
      service.getPaymentLinkStatus.mockResolvedValue(mockStatusResponse);

      await controller.getPaymentLinkStatus(
        "testuser",
        "100",
        "XLM",
        undefined,
        "XLM,USDC,AQUA",
      );

      expect(service.getPaymentLinkStatus).toHaveBeenCalledWith(
        expect.objectContaining({
          acceptedAssets: ["XLM", "USDC", "AQUA"],
        }),
      );
    });

    it("should trim whitespace from acceptedAssets entries", async () => {
      service.getPaymentLinkStatus.mockResolvedValue(mockStatusResponse);

      await controller.getPaymentLinkStatus(
        "testuser",
        "100",
        "XLM",
        undefined,
        " XLM , USDC ",
      );

      expect(service.getPaymentLinkStatus).toHaveBeenCalledWith(
        expect.objectContaining({
          acceptedAssets: ["XLM", "USDC"],
        }),
      );
    });
  });
});
