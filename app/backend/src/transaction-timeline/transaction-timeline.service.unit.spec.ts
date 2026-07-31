import { Test, TestingModule } from "@nestjs/testing";
import { TransactionTimelineService } from "./transaction-timeline.service";
import { SupabaseService } from "../supabase/supabase.service";
import { HorizonService } from "../transactions/horizon.service";
import type { TimelineResponse } from "./transaction-timeline.types";

// ── Helpers ──────────────────────────────────────────────────────────────────

const TX_HASH = "abc123txhash000";

function makeHorizonResp(items: object[] = []) {
  return { items, nextCursor: undefined };
}

function buildSupabaseMock(
  overrides: {
    payment?: object[] | null;
    refund?: object[] | null;
    webhook?: object[] | null;
    contract?: object[] | null;
    paymentError?: object;
    refundError?: object;
    webhookError?: object;
    contractError?: object;
  } = {},
) {
  const makeChain = (rows: object[] | null, err: object | null = null) => {
    const chain: Record<string, jest.Mock> = {};
    const terminal = jest.fn().mockResolvedValue({ data: rows, error: err });
    // Every chain method returns `chain` for further chaining AND resolves as a
    // thenable so that `await client.from(...).select(...).eq(...)` works even
    // when the last chained call is not `.limit()`.
    const thenable = {
      then: jest.fn((resolve: (v: unknown) => void) =>
        resolve({ data: rows, error: err }),
      ),
    };
    for (const key of [
      "select",
      "from",
      "eq",
      "or",
      "ilike",
      "order",
      "limit",
    ]) {
      chain[key] = jest.fn().mockReturnValue(chain);
    }
    // Make the chain itself thenable so any terminal call resolves
    Object.assign(chain, { then: thenable.then });
    return chain;
  };

  const tableChains: Record<string, ReturnType<typeof makeChain>> = {
    payment_records: makeChain(
      overrides.payment ?? [],
      overrides.paymentError ?? null,
    ),
    refund_attempts: makeChain(
      overrides.refund ?? [],
      overrides.refundError ?? null,
    ),
    notification_log: makeChain(
      overrides.webhook ?? [],
      overrides.webhookError ?? null,
    ),
    contract_change_webhooks: makeChain(
      overrides.contract ?? [],
      overrides.contractError ?? null,
    ),
  };

  const getClient = jest.fn(() => ({
    from: jest.fn((table: string) => {
      return tableChains[table] ?? makeChain([]);
    }),
  }));

  return { getClient };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("TransactionTimelineService", () => {
  let service: TransactionTimelineService;
  let horizonService: { getPayments: jest.Mock };

  async function init(
    supabaseMock: ReturnType<typeof buildSupabaseMock>,
    horizonMock?: object,
  ) {
    horizonService = {
      getPayments: jest
        .fn()
        .mockResolvedValue(horizonMock ?? makeHorizonResp()),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TransactionTimelineService,
        { provide: SupabaseService, useValue: supabaseMock },
        { provide: HorizonService, useValue: horizonService },
      ],
    }).compile();

    service = module.get(TransactionTimelineService);
  }

  // ── Complete timeline ────────────────────────────────────────────────────

  describe("complete timeline", () => {
    it("aggregates payment, refund, webhook, and contract items", async () => {
      const paymentRows = [
        {
          id: "p1",
          status: "completed",
          created_at: "2024-01-03T00:00:00Z",
          amount: "10",
          asset_code: "USDC",
          sender_address: "GABC",
          receiver_address: "GDEF",
        },
      ];
      const refundRows = [
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "CUSTOMER_REQUEST",
          status: "approved",
          actor_id: "user1",
          created_at: "2024-01-02T00:00:00Z",
        },
      ];
      const webhookRows = [
        {
          id: "w1",
          event_type: "payment.received",
          event_id: TX_HASH,
          status: "sent",
          attempts: 1,
          last_error: null,
          webhook_response_status: 200,
          webhook_delivered_at: "2024-01-03T01:00:00Z",
          created_at: "2024-01-03T00:30:00Z",
        },
      ];
      const contractRows = [
        {
          id: "ctr1",
          webhook_url: "https://example.com/hook",
          enabled: true,
          created_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-03T02:00:00Z",
        },
      ];

      await init(
        buildSupabaseMock({
          payment: paymentRows,
          refund: refundRows,
          webhook: webhookRows,
          contract: contractRows,
        }),
      );

      const result: TimelineResponse = await service.getTimeline({
        txHash: TX_HASH,
        address: "GABC",
      });

      expect(result.isPartial).toBe(false);
      expect(result.failedSources).toHaveLength(0);
      expect(result.items.length).toBeGreaterThan(0);

      const kinds = result.items.map((i) => i.kind);
      // Payment comes from Horizon (address provided); refund, webhook, contract from DB
      expect(kinds).toContain("refund");
      expect(kinds).toContain("webhook_delivery");
      expect(kinds).toContain("contract_event");
    });

    it("orders items descending by timestamp", async () => {
      const refundRows = [
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "DUPLICATE",
          status: "pending",
          actor_id: "u1",
          created_at: "2024-01-01T00:00:00Z",
        },
        {
          id: "r2",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "FRAUD",
          status: "rejected",
          actor_id: "u2",
          created_at: "2024-01-03T00:00:00Z",
        },
        {
          id: "r3",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "TECHNICAL_ERROR",
          status: "approved",
          actor_id: "u3",
          created_at: "2024-01-02T00:00:00Z",
        },
      ];

      await init(buildSupabaseMock({ refund: refundRows }));

      const result = await service.getTimeline({
        txHash: TX_HASH,
        kind: "refund",
      });

      const timestamps = result.items.map((i) =>
        new Date(i.timestamp).getTime(),
      );
      for (let j = 1; j < timestamps.length; j++) {
        expect(timestamps[j - 1]).toBeGreaterThanOrEqual(timestamps[j]);
      }
    });

    it("deduplicates items with the same id", async () => {
      // Two rows with the same ID would normally not happen but the dedup must handle it
      const refundRows = [
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "FRAUD",
          status: "pending",
          actor_id: "u1",
          created_at: "2024-01-01T00:00:00Z",
        },
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "FRAUD",
          status: "pending",
          actor_id: "u1",
          created_at: "2024-01-01T00:00:00Z",
        },
      ];

      await init(buildSupabaseMock({ refund: refundRows }));

      const result = await service.getTimeline({
        txHash: TX_HASH,
        kind: "refund",
      });
      const ids = result.items.map((i) => i.id);
      const unique = new Set(ids);
      expect(unique.size).toBe(ids.length);
    });
  });

  // ── Partial timeline ─────────────────────────────────────────────────────

  describe("partial timeline", () => {
    it("returns isPartial=true when one source throws", async () => {
      await init(
        buildSupabaseMock({
          refundError: { message: "DB error", code: "PGRST000" },
        }),
      );

      const result = await service.getTimeline({ txHash: TX_HASH });

      expect(result.isPartial).toBe(true);
      expect(result.failedSources).toContain("refund");
    });

    it("still returns items from healthy sources when one fails", async () => {
      const webhookRows = [
        {
          id: "w1",
          event_type: "payment.received",
          event_id: TX_HASH,
          status: "sent",
          attempts: 1,
          last_error: null,
          webhook_response_status: 200,
          webhook_delivered_at: null,
          created_at: "2024-01-01T00:00:00Z",
        },
      ];

      await init(
        buildSupabaseMock({
          refundError: { message: "DB error", code: "PGRST000" },
          webhook: webhookRows,
        }),
      );

      const result = await service.getTimeline({
        txHash: TX_HASH,
        address: "GABC",
      });

      expect(result.isPartial).toBe(true);
      const kinds = result.items.map((i) => i.kind);
      expect(kinds).toContain("webhook_delivery");
    });

    it("returns empty items array (not an error) when all sources have no data", async () => {
      await init(buildSupabaseMock({}));

      const result = await service.getTimeline({ txHash: TX_HASH });

      expect(result.items).toHaveLength(0);
      expect(result.isPartial).toBe(false);
      expect(result.txHash).toBe(TX_HASH);
    });
  });

  // ── Filtering ────────────────────────────────────────────────────────────

  describe("kind filter", () => {
    it("limits results to the specified kind", async () => {
      const refundRows = [
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "FRAUD",
          status: "pending",
          actor_id: "u1",
          created_at: "2024-01-01T00:00:00Z",
        },
      ];

      await init(buildSupabaseMock({ refund: refundRows }));

      const result = await service.getTimeline({
        txHash: TX_HASH,
        kind: "refund",
      });

      const nonRefund = result.items.filter((i) => i.kind !== "refund");
      expect(nonRefund).toHaveLength(0);
    });
  });

  // ── Limit ────────────────────────────────────────────────────────────────

  describe("limit", () => {
    it("caps results at the requested limit", async () => {
      const refundRows = Array.from({ length: 10 }, (_, k) => ({
        id: `r${k}`,
        entity_type: "payment",
        entity_id: TX_HASH,
        reason_code: "FRAUD",
        status: "pending",
        actor_id: "u1",
        created_at: `2024-01-${String(k + 1).padStart(2, "0")}T00:00:00Z`,
      }));

      await init(buildSupabaseMock({ refund: refundRows }));

      const result = await service.getTimeline({
        txHash: TX_HASH,
        kind: "refund",
        limit: 3,
      });

      expect(result.items).toHaveLength(3);
      expect(result.total).toBe(10);
    });
  });

  // ── Receipt refs ─────────────────────────────────────────────────────────

  describe("receipt references", () => {
    it("attaches a receipt ref to payment items", async () => {
      const horizonItems = [
        {
          txHash: TX_HASH,
          amount: "5.00",
          asset: "XLM",
          source: "GABC",
          destination: "GDEF",
          memo: undefined,
          timestamp: "2024-01-01T00:00:00Z",
          status: "Success",
          pagingToken: "tok1",
        },
      ];

      await init(buildSupabaseMock({}), makeHorizonResp(horizonItems));

      const result = await service.getTimeline({
        txHash: TX_HASH,
        address: "GABC",
        kind: "payment",
      });

      const payItems = result.items.filter((i) => i.kind === "payment");
      for (const item of payItems) {
        expect(item.receiptRef).not.toBeNull();
        expect(item.receiptRef?.txHash).toBe(TX_HASH);
        expect(item.receiptRef?.url).toContain(TX_HASH);
      }
    });

    it("refund items have no receipt ref", async () => {
      const refundRows = [
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "FRAUD",
          status: "approved",
          actor_id: "u1",
          created_at: "2024-01-01T00:00:00Z",
        },
      ];

      await init(buildSupabaseMock({ refund: refundRows }));

      const result = await service.getTimeline({
        txHash: TX_HASH,
        kind: "refund",
      });

      for (const item of result.items) {
        expect(item.receiptRef).toBeNull();
      }
    });
  });

  // ── Correlation IDs ──────────────────────────────────────────────────────

  describe("correlation ids", () => {
    it("sets correlationId to the txHash on all item kinds", async () => {
      const refundRows = [
        {
          id: "r1",
          entity_type: "payment",
          entity_id: TX_HASH,
          reason_code: "FRAUD",
          status: "pending",
          actor_id: "u1",
          created_at: "2024-01-01T00:00:00Z",
        },
      ];

      await init(buildSupabaseMock({ refund: refundRows }));

      const result = await service.getTimeline({ txHash: TX_HASH });

      for (const item of result.items) {
        expect(item.correlationId).toBe(TX_HASH);
      }
    });
  });
});
