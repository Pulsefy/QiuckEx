import { WebhookService } from "../webhook.service";
import {
  redactSensitiveText,
  redactPayloadMetadata,
} from "../utils/redaction.util";
import type { NotificationPreference } from "../types/notification.types";

describe("Webhook Delivery History Query API & Redaction", () => {
  const PUBLIC_KEY_1 = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
  const PUBLIC_KEY_2 = "GBBZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

  describe("Redaction Rules", () => {
    it("should redact secrets, tokens, Stellar seeds, and sensitive headers", () => {
      const rawText =
        "Failed to deliver whsec_1234567890secret value with token Bearer eyJhbGciOiJIUzI1Ni... and seed SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const redacted = redactSensitiveText(rawText);

      expect(redacted).not.toContain("whsec_1234567890secret");
      expect(redacted).not.toContain("SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
      expect(redacted).toContain("whsec_••••••••");
      expect(redacted).toContain("S••••••••");
      expect(redacted).toContain("Bearer••••••••");
    });

    it("should recursively redact sensitive keys in payload metadata objects", () => {
      const payload = {
        event_id: "evt_100",
        amount_stroops: "1000000",
        secret: "whsec_supersecretkey",
        api_key: "key_99999",
        nested: {
          token: "auth_token_xyz",
          asset_code: "USDC",
        },
      };

      const redacted = redactPayloadMetadata(payload);

      expect(redacted.secret).toBe("••••••••");
      expect(redacted.api_key).toBe("••••••••");
      expect((redacted.nested as Record<string, unknown>).token).toBe("••••••••");
      expect((redacted.nested as Record<string, unknown>).asset_code).toBe("USDC");
    });
  });

  describe("WebhookService Delivery History & Access Control", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let mockPrefsRepo: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let mockLogRepo: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let mockReplayService: any;
    let service: WebhookService;

    const sampleWebhookPref: NotificationPreference = {
      id: "webhook-uuid-1",
      publicKey: PUBLIC_KEY_1,
      channel: "webhook",
      webhookUrl: "https://example.com/webhook",
      webhookSecret: "whsec_test",
      events: null,
      minAmountStroops: 0n,
      enabled: true,
    };

    beforeEach(() => {
      mockPrefsRepo = {
        getWebhookById: jest.fn(),
        getWebhooksByPublicKey: jest.fn().mockResolvedValue([sampleWebhookPref]),
        getWebhooksByPublicKeyPaginated: jest.fn(),
      };

      mockLogRepo = {
        getWebhookDeliveryLogsPaginated: jest.fn(),
        getWebhookDeliveryLogById: jest.fn(),
        getWebhookStats: jest.fn(),
      };

      mockReplayService = {
        replayDelivery: jest.fn(),
        getDeliveryStatus: jest.fn(),
        listReplayHistory: jest.fn(),
      };

      service = new WebhookService(mockPrefsRepo, mockLogRepo, mockReplayService);
    });

    it("should query delivery history with status and eventType filters", async () => {
      mockLogRepo.getWebhookDeliveryLogsPaginated.mockResolvedValue({
        data: [
          {
            id: "log-1",
            eventType: "payment.received",
            eventId: "tx-1",
            status: "failed",
            attempts: 3,
            lastError: "Endpoint error whsec_secretkey",
            createdAt: "2026-08-24T07:00:00Z",
            updatedAt: "2026-08-24T07:00:01Z",
            payloadMetadata: { event_id: "tx-1", secret: "whsec_secretkey" },
          },
        ],
        next_cursor: "cursor-2",
        has_more: true,
      });

      const result = await service.getDeliveryHistory(PUBLIC_KEY_1, {
        status: "failed",
        eventType: "payment.received",
        limit: 10,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].status).toBe("failed");
      expect(result.data[0].lastError).toContain("whsec_••••••••");
      expect(result.data[0].payloadMetadata?.secret).toBe("••••••••");
      expect(mockLogRepo.getWebhookDeliveryLogsPaginated).toHaveBeenCalledWith(
        PUBLIC_KEY_1,
        10,
        undefined,
        { status: "failed", eventType: "payment.received" },
      );
    });

    it("should enforce access control when endpoint parameter belongs to another public key", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue({
        ...sampleWebhookPref,
        id: "foreign-webhook",
        publicKey: PUBLIC_KEY_2,
      });

      const result = await service.getDeliveryHistory(PUBLIC_KEY_1, {
        endpoint: "foreign-webhook",
      });

      expect(result.data).toEqual([]);
      expect(mockLogRepo.getWebhookDeliveryLogsPaginated).not.toHaveBeenCalled();
    });

    it("should fetch single delivery detail with attempt history and redacted metadata", async () => {
      mockLogRepo.getWebhookDeliveryLogById.mockResolvedValue({
        id: "log-detail-1",
        eventType: "EscrowDeposited",
        eventId: "escrow-100",
        status: "dlq",
        attempts: 3,
        lastError: "HTTP 500 whsec_secret",
        httpStatus: 500,
        responseBody: "Internal Server Error token_123",
        createdAt: "2026-08-24T06:00:00Z",
        updatedAt: "2026-08-24T06:30:00Z",
        payloadMetadata: { token: "token_123" },
      });

      const detail = await service.getDeliveryDetail(PUBLIC_KEY_1, "log-detail-1");

      expect(detail).not.toBeNull();
      expect(detail?.id).toBe("log-detail-1");
      expect(detail?.status).toBe("dlq");
      expect(detail?.dlqReason).toContain("HTTP 500");
      expect(detail?.attemptHistory).toHaveLength(3);
      expect(detail?.payloadMetadata?.token).toBe("••••••••");
    });

    it("should return empty result when specified endpoint ID does not exist", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(null);

      const result = await service.getDeliveryHistory(PUBLIC_KEY_1, {
        endpoint: "non-existent-endpoint",
      });

      expect(result.data).toEqual([]);
      expect(result.next_cursor).toBeNull();
      expect(result.has_more).toBe(false);
      expect(mockLogRepo.getWebhookDeliveryLogsPaginated).not.toHaveBeenCalled();
    });

    it("should support cursor pagination in delivery history query", async () => {
      mockLogRepo.getWebhookDeliveryLogsPaginated.mockResolvedValue({
        data: [
          {
            id: "log-2",
            eventType: "payment.received",
            eventId: "tx-2",
            status: "sent",
            attempts: 1,
            createdAt: "2026-08-24T08:00:00Z",
            updatedAt: "2026-08-24T08:00:01Z",
          },
        ],
        next_cursor: "eyJwayI6IjIwMjYtMDgtMjRUMDg6MDA6MDBaIiwiaWQiOiJsb2ctMiJ9",
        has_more: true,
      });

      const result = await service.getDeliveryHistory(PUBLIC_KEY_1, {
        cursor: "previous-cursor",
        limit: 5,
      });

      expect(result.data).toHaveLength(1);
      expect(result.next_cursor).toBe("eyJwayI6IjIwMjYtMDgtMjRUMDg6MDA6MDBaIiwiaWQiOiJsb2ctMiJ9");
      expect(result.has_more).toBe(true);
      expect(mockLogRepo.getWebhookDeliveryLogsPaginated).toHaveBeenCalledWith(
        PUBLIC_KEY_1,
        5,
        "previous-cursor",
        { status: undefined, eventType: undefined },
      );
    });
  });
});
