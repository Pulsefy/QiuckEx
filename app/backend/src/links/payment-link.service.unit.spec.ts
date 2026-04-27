import { Test, TestingModule } from "@nestjs/testing";
import { NotFoundException } from "@nestjs/common";
import { PaymentLinkService } from "./payment-link.service";
import { HorizonService } from "../transactions/horizon.service";
import { SupabaseService } from "../supabase/supabase.service";
import { LinksService } from "./links.service";
import { LinkState } from "./link-state-machine";

describe("PaymentLinkService", () => {
  let service: PaymentLinkService;
  let horizonService: jest.Mocked<HorizonService>;
  let supabaseService: jest.Mocked<SupabaseService>;
  let linksService: jest.Mocked<LinksService>;

  const mockUsernameRecord = {
    public_key: "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
  };

  const mockMetadata = {
    amount: "100.0000000",
    asset: "XLM",
    username: "testuser",
    memo: "Test payment",
    memoType: "text",
    privacy: false,
    expiresAt: new Date(Date.now() + 86400000 * 30), // 30 days from now
    acceptedAssets: ["XLM", "USDC"],
    swapOptions: [],
    canonical: "amount=100.0000000&asset=XLM&memo=Test%20payment",
    metadata: {
      normalized: true,
      assetType: "native",
      linkType: "standard",
      securityLevel: "medium",
    },
  };

  const mockPayments = {
    items: [
      {
        amount: "100.0000000",
        asset: "XLM",
        memo: "Test payment",
        timestamp: "2026-04-27T10:30:00Z",
        txHash: "abc123def456",
        source: "GSOURCE123",
        destination: "GDESTINATION456",
        status: "Success" as const,
        pagingToken: "token1",
      },
    ],
    nextCursor: "token1",
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PaymentLinkService,
        {
          provide: HorizonService,
          useValue: {
            getPayments: jest.fn(),
          },
        },
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn().mockReturnValue({
              from: jest.fn().mockReturnValue({
                select: jest.fn().mockReturnValue({
                  eq: jest.fn().mockReturnValue({
                    single: jest.fn(),
                  }),
                }),
              }),
            }),
          },
        },
        {
          provide: LinksService,
          useValue: {
            generateMetadata: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<PaymentLinkService>(PaymentLinkService);
    horizonService = module.get(HorizonService);
    supabaseService = module.get(SupabaseService);
    linksService = module.get(LinksService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("getPaymentLinkStatus", () => {
    it("should return ACTIVE state when no payment found", async () => {
      // Mock username lookup
      (supabaseService.getClient().from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest
              .fn()
              .mockResolvedValue({ data: mockUsernameRecord, error: null }),
          }),
        }),
      });

      // Mock metadata generation
      linksService.generateMetadata.mockResolvedValue(mockMetadata);

      // Mock no payments found
      horizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const result = await service.getPaymentLinkStatus({
        username: "testuser",
        amount: 100,
        asset: "XLM",
        memo: "Test payment",
      });

      expect(result.state).toBe(LinkState.ACTIVE);
      expect(result.username).toBe("testuser");
      expect(result.amount).toBe("100.0000000");
      expect(result.transactionHash).toBeNull();
      expect(result.userMessage).toContain("active");
    });

    it("should return PAID state when matching payment found", async () => {
      // Mock username lookup
      (supabaseService.getClient().from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest
              .fn()
              .mockResolvedValue({ data: mockUsernameRecord, error: null }),
          }),
        }),
      });

      // Mock metadata generation
      linksService.generateMetadata.mockResolvedValue(mockMetadata);

      // Mock payment found
      horizonService.getPayments.mockResolvedValue(mockPayments);

      const result = await service.getPaymentLinkStatus({
        username: "testuser",
        amount: 100,
        asset: "XLM",
        memo: "Test payment",
      });

      expect(result.state).toBe(LinkState.PAID);
      expect(result.transactionHash).toBe("abc123def456");
      expect(result.userMessage).toContain("completed");
    });

    it("should return EXPIRED state when expiresAt is in the past", async () => {
      const expiredMetadata = {
        ...mockMetadata,
        expiresAt: new Date(Date.now() - 86400000), // Yesterday
      };

      // Mock username lookup
      (supabaseService.getClient().from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest
              .fn()
              .mockResolvedValue({ data: mockUsernameRecord, error: null }),
          }),
        }),
      });

      // Mock metadata generation
      linksService.generateMetadata.mockResolvedValue(expiredMetadata);

      // Mock no payments found
      horizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const result = await service.getPaymentLinkStatus({
        username: "testuser",
        amount: 100,
      });

      expect(result.state).toBe(LinkState.EXPIRED);
      expect(result.userMessage).toContain("expired");
    });

    it("should throw NotFoundException when username not found", async () => {
      // Mock username lookup failure
      (supabaseService.getClient().from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest
              .fn()
              .mockResolvedValue({ data: null, error: new Error("Not found") }),
          }),
        }),
      });

      await expect(
        service.getPaymentLinkStatus({
          username: "nonexistent",
          amount: 100,
        }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe("determineLinkState", () => {
    it("should prioritize PAID state over EXPIRED", () => {
      const expiredMetadata = {
        ...mockMetadata,
        expiresAt: new Date(Date.now() - 86400000),
      };

      const paymentInfo = {
        transactionHash: "abc123",
        paidAt: new Date(),
      };

      // Access private method for testing
      const state = (
        service as unknown as {
          determineLinkState: (
            metadata: Record<string, unknown>,
            paymentInfo: { transactionHash: string; paidAt: Date } | null,
          ) => LinkState;
        }
      ).determineLinkState(expiredMetadata, paymentInfo);
      expect(state).toBe(LinkState.PAID);
    });
  });
});
