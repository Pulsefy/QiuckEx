/**
 * Integration test: Payment flow end-to-end
 *
 * Tests the full payment lifecycle:
 *   1. Create a payment link (via PaymentLinkService)
 *   2. Check status → ACTIVE
 *   3. Simulate on-chain payment (mock Horizon)
 *   4. Check status → PAID
 *   5. Simulate link expiry
 *   6. Verify state machine transitions
 *
 * External services (Horizon, Supabase) are mocked.
 */
import { Test, TestingModule } from "@nestjs/testing";
import { NotFoundException } from "@nestjs/common";
import { PaymentLinkService } from "../src/links/payment-link.service";
import { HorizonService } from "../src/transactions/horizon.service";
import { SupabaseService } from "../src/supabase/supabase.service";
import { LinksService } from "../src/links/links.service";
import { LinkState } from "../src/links/link-state-machine";
import { PaymentLinkExpiryService } from "../src/links/payment-link-expiry.service";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { AuditService } from "../src/audit/audit.service";
import { MetricsService } from "../src/metrics/metrics.service";

describe("Payment Flow Integration", () => {
  let paymentLinkService: PaymentLinkService;
  let expiryService: PaymentLinkExpiryService;
  let horizonService: jest.Mocked<HorizonService>;
  let supabaseService: jest.Mocked<SupabaseService>;
  let linksService: jest.Mocked<LinksService>;
  let auditService: jest.Mocked<AuditService>;
  let events: EventEmitter2;

  const DEST_PUBLIC_KEY = "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

  const baseMetadata = {
    amount: "50.0000000",
    asset: "XLM",
    username: "alice",
    memo: "Coffee payment",
    memoType: "text" as const,
    privacy: false,
    expiresAt: new Date(Date.now() + 86400000 * 30),
    acceptedAssets: ["XLM"],
    swapOptions: null,
    canonical: "amount=50.0000000&asset=XLM&memo=Coffee%20payment",
    metadata: {
      normalized: false,
      assetType: "native",
      linkType: "standard",
      securityLevel: "medium",
    },
  };

  beforeEach(async () => {
    // Supabase chainable mock
    const supabaseBuilder = {
      from: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      single: jest.fn(),
      update: jest.fn().mockReturnThis(),
      not: jest.fn().mockReturnThis(),
      lte: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue({ data: [], error: null }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PaymentLinkService,
        PaymentLinkExpiryService,
        {
          provide: HorizonService,
          useValue: { getPayments: jest.fn() },
        },
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn().mockReturnValue(supabaseBuilder),
          },
        },
        {
          provide: LinksService,
          useValue: { generateMetadata: jest.fn() },
        },
        {
          provide: EventEmitter2,
          useValue: new EventEmitter2(),
        },
        {
          provide: AuditService,
          useValue: { log: jest.fn().mockResolvedValue(undefined) },
        },
        {
          provide: MetricsService,
          useValue: {
            recordPaymentLinkExpired: jest.fn(),
            recordRequestDuration: jest.fn(),
            recordError: jest.fn(),
            getRegistry: jest.fn(() => ({ getMetricsAsJSON: jest.fn() })),
          },
        },
      ],
    }).compile();

    paymentLinkService = module.get(PaymentLinkService);
    expiryService = module.get(PaymentLinkExpiryService);
    horizonService = module.get(HorizonService);
    supabaseService = module.get(SupabaseService);
    linksService = module.get(LinksService);
    auditService = module.get(AuditService);
    events = module.get(EventEmitter2);
  });

  // -------------------------------------------------------------------------
  // Scenario 1: Full payment lifecycle (create → pay)
  // -------------------------------------------------------------------------
  describe("Scenario 1: Payment link created then paid", () => {
    it("should transition from ACTIVE to PAID when matching payment arrives", async () => {
      // Step 1: Username lookup succeeds
      const client = supabaseService.getClient();
      (client.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { public_key: DEST_PUBLIC_KEY },
              error: null,
            }),
          }),
        }),
      });

      // Step 2: Metadata generated
      linksService.generateMetadata.mockResolvedValue(baseMetadata);

      // Step 3: No payment found yet → ACTIVE
      horizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const statusBefore = await paymentLinkService.getPaymentLinkStatus({
        username: "alice",
        amount: 50,
        asset: "XLM",
        memo: "Coffee payment",
      });

      expect(statusBefore.state).toBe(LinkState.ACTIVE);
      expect(statusBefore.transactionHash).toBeNull();
      expect(statusBefore.availableActions).toContain("pay");

      // Step 4: Simulate payment arriving on-chain
      horizonService.getPayments.mockResolvedValue({
        items: [
          {
            amount: "50.0000000",
            asset: "XLM",
            memo: "Coffee payment",
            timestamp: new Date().toISOString(),
            txHash: "tx_hash_abc123",
            source: "GSOURCE123",
            destination: DEST_PUBLIC_KEY,
            status: "Success" as const,
            pagingToken: "tok1",
          },
        ],
        nextCursor: "tok1",
      });

      const statusAfter = await paymentLinkService.getPaymentLinkStatus({
        username: "alice",
        amount: 50,
        asset: "XLM",
        memo: "Coffee payment",
      });

      expect(statusAfter.state).toBe(LinkState.PAID);
      expect(statusAfter.transactionHash).toBe("tx_hash_abc123");
      expect(statusAfter.paidAt).toBeInstanceOf(Date);
      expect(statusAfter.userMessage).toContain("completed");
      expect(statusAfter.availableActions).toContain("view_transaction");
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 2: Payment link expires without payment
  // -------------------------------------------------------------------------
  describe("Scenario 2: Payment link expires without payment", () => {
    it("should return EXPIRED when link expires without payment", async () => {
      const expiredMetadata = {
        ...baseMetadata,
        expiresAt: new Date(Date.now() - 86400000), // Yesterday
      };

      const client = supabaseService.getClient();
      (client.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { public_key: DEST_PUBLIC_KEY },
              error: null,
            }),
          }),
        }),
      });

      linksService.generateMetadata.mockResolvedValue(expiredMetadata);

      horizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const status = await paymentLinkService.getPaymentLinkStatus({
        username: "alice",
        amount: 50,
      });

      expect(status.state).toBe(LinkState.EXPIRED);
      expect(status.userMessage).toContain("expired");
      expect(status.availableActions).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 3: Username not found
  // -------------------------------------------------------------------------
  describe("Scenario 3: Username not found", () => {
    it("should throw NotFoundException for unknown username", async () => {
      const client = supabaseService.getClient();
      (client.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: null,
              error: new Error("Not found"),
            }),
          }),
        }),
      });

      await expect(
        paymentLinkService.getPaymentLinkStatus({
          username: "nonexistent_user",
          amount: 50,
        }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 4: Payment with wrong amount does not match
  // -------------------------------------------------------------------------
  describe("Scenario 4: Payment amount mismatch", () => {
    it("should remain ACTIVE when payment amount does not match", async () => {
      const client = supabaseService.getClient();
      (client.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { public_key: DEST_PUBLIC_KEY },
              error: null,
            }),
          }),
        }),
      });

      linksService.generateMetadata.mockResolvedValue(baseMetadata);

      // Payment with wrong amount
      horizonService.getPayments.mockResolvedValue({
        items: [
          {
            amount: "25.0000000", // Wrong amount!
            asset: "XLM",
            memo: "Coffee payment",
            timestamp: new Date().toISOString(),
            txHash: "tx_wrong_amount",
            source: "GSOURCE123",
            destination: DEST_PUBLIC_KEY,
            status: "Success" as const,
            pagingToken: "tok1",
          },
        ],
        nextCursor: "tok1",
      });

      const status = await paymentLinkService.getPaymentLinkStatus({
        username: "alice",
        amount: 50,
        asset: "XLM",
        memo: "Coffee payment",
      });

      expect(status.state).toBe(LinkState.ACTIVE);
      expect(status.transactionHash).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 5: Payment with wrong asset does not match
  // -------------------------------------------------------------------------
  describe("Scenario 5: Payment asset mismatch", () => {
    it("should remain ACTIVE when payment asset does not match", async () => {
      const client = supabaseService.getClient();
      (client.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { public_key: DEST_PUBLIC_KEY },
              error: null,
            }),
          }),
        }),
      });

      linksService.generateMetadata.mockResolvedValue(baseMetadata);

      // Payment with wrong asset
      horizonService.getPayments.mockResolvedValue({
        items: [
          {
            amount: "50.0000000",
            asset: "USDC", // Wrong asset!
            memo: "Coffee payment",
            timestamp: new Date().toISOString(),
            txHash: "tx_wrong_asset",
            source: "GSOURCE123",
            destination: DEST_PUBLIC_KEY,
            status: "Success" as const,
            pagingToken: "tok1",
          },
        ],
        nextCursor: "tok1",
      });

      const status = await paymentLinkService.getPaymentLinkStatus({
        username: "alice",
        amount: 50,
        asset: "XLM",
        memo: "Coffee payment",
      });

      expect(status.state).toBe(LinkState.ACTIVE);
      expect(status.transactionHash).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 6: Expiry sweep marks links expired
  // -------------------------------------------------------------------------
  describe("Scenario 6: Expiry sweep marks expired links", () => {
    it("should mark expired links and emit events", async () => {
      const expiredRow = {
        id: "link-uuid-1",
        owner_public_key: "GOWNER",
        destination_public_key: DEST_PUBLIC_KEY,
        amount: "50.0000000",
        asset_code: "XLM",
        memo: "Coffee payment",
        expires_at: new Date(Date.now() - 86400000).toISOString(),
        matched_tx_hash: null,
        matched_at: null,
      };

      const client = supabaseService.getClient();
      // The builder chain ends at select() and insert()
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any).select = jest.fn().mockResolvedValue({
        data: [expiredRow],
        error: null,
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any).insert = jest.fn().mockResolvedValue({
        data: [{ id: "audit-1" }],
        error: null,
      });

      const emitSpy = jest.spyOn(events, "emit");

      const count = await expiryService.runExpirySweep("sweep-run-1");

      expect(count).toBe(1);
      expect(auditService.log).toHaveBeenCalledWith(
        "system:expiry-worker",
        "payment_link.expired",
        "link-uuid-1",
        expect.objectContaining({ runId: "sweep-run-1" }),
      );
      expect(emitSpy).toHaveBeenCalledWith(
        "payment.link.expired",
        expect.objectContaining({ linkId: "link-uuid-1" }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 7: Horizon failure is handled gracefully
  // -------------------------------------------------------------------------
  describe("Scenario 7: Horizon failure handled gracefully", () => {
    it("should return ACTIVE when Horizon is unavailable", async () => {
      const client = supabaseService.getClient();
      (client.from as jest.Mock).mockReturnValue({
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            single: jest.fn().mockResolvedValue({
              data: { public_key: DEST_PUBLIC_KEY },
              error: null,
            }),
          }),
        }),
      });

      linksService.generateMetadata.mockResolvedValue(baseMetadata);

      // Horizon throws
      horizonService.getPayments.mockRejectedValue(new Error("Horizon down"));

      const status = await paymentLinkService.getPaymentLinkStatus({
        username: "alice",
        amount: 50,
        asset: "XLM",
        memo: "Coffee payment",
      });

      // Should assume not paid when Horizon is down
      expect(status.state).toBe(LinkState.ACTIVE);
      expect(status.transactionHash).toBeNull();
    });
  });
});
