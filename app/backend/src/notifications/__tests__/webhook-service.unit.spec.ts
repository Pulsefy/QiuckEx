import { WebhookService } from "../webhook.service";
import type { NotificationPreference } from "../types/notification.types";

describe("WebhookService", () => {
  let service: WebhookService;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockPrefsRepo: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockLogRepo: any;

  const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

  function makePref(
    overrides: Partial<NotificationPreference> = {},
  ): NotificationPreference {
    return {
      id: "webhook-1",
      publicKey: PUBLIC_KEY,
      channel: "webhook",
      webhookUrl: "https://example.com/webhook",
      webhookSecret: "whsec_test",
      events: null,
      minAmountStroops: 0n,
      enabled: true,
      ...overrides,
    };
  }

  beforeEach(() => {
    mockPrefsRepo = {
      upsertPreference: jest.fn(),
      getWebhookById: jest.fn(),
      getWebhooksByPublicKey: jest.fn(),
      getWebhooksByPublicKeyPaginated: jest.fn(),
      deleteWebhook: jest.fn(),
      regenerateWebhookSecret: jest.fn(),
    };

    mockLogRepo = {
      getWebhookDeliveryLogs: jest.fn(),
      getWebhookStats: jest.fn(),
    };

    const mockRetryScheduler = {
      redeliver: jest.fn().mockResolvedValue(true),
    };

    service = new WebhookService(mockPrefsRepo, mockLogRepo, mockRetryScheduler as never);
  });

  describe("createWebhook", () => {
    it("should create webhook with auto-generated secret", async () => {
      mockPrefsRepo.upsertPreference.mockResolvedValue(makePref());

      await service.createWebhook(PUBLIC_KEY, {
        webhookUrl: "https://example.com/webhook",
      });

      expect(mockPrefsRepo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "webhook",
        expect.objectContaining({
          webhookUrl: "https://example.com/webhook",
          enabled: true,
        }),
      );

      const call = mockPrefsRepo.upsertPreference.mock.calls[0];
      expect(call[2].webhookSecret).toMatch(/^whsec_[a-f0-9]{64}$/);
    });

    it("should use provided secret", async () => {
      mockPrefsRepo.upsertPreference.mockResolvedValue(
        makePref({ webhookSecret: "custom-secret" }),
      );

      await service.createWebhook(PUBLIC_KEY, {
        webhookUrl: "https://example.com/webhook",
        secret: "custom-secret",
      });

      expect(mockPrefsRepo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "webhook",
        expect.objectContaining({
          webhookSecret: "custom-secret",
        }),
      );
    });

    it("should set event filters when provided", async () => {
      mockPrefsRepo.upsertPreference.mockResolvedValue(makePref());

      await service.createWebhook(PUBLIC_KEY, {
        webhookUrl: "https://example.com/webhook",
        events: ["payment.received", "EscrowDeposited"],
      });

      expect(mockPrefsRepo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "webhook",
        expect.objectContaining({
          events: ["payment.received", "EscrowDeposited"],
        }),
      );
    });

    it("should set minimum amount threshold", async () => {
      mockPrefsRepo.upsertPreference.mockResolvedValue(makePref());

      await service.createWebhook(PUBLIC_KEY, {
        webhookUrl: "https://example.com/webhook",
        minAmountStroops: 100000000,
      });

      expect(mockPrefsRepo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "webhook",
        expect.objectContaining({
          minAmountStroops: 100000000n,
        }),
      );
    });
  });

  describe("listWebhooks", () => {
    it("should return paginated webhooks for a public key", async () => {
      const prefs = [
        makePref({ id: "w1" }),
        makePref({ id: "w2", webhookUrl: "https://other.com/hook" }),
      ];
      mockPrefsRepo.getWebhooksByPublicKeyPaginated.mockResolvedValue({
        data: prefs,
        next_cursor: "next-c",
        has_more: true,
      });

      const result = await service.listWebhooks(PUBLIC_KEY, "cursor-1", 10);

      expect(result.data).toHaveLength(2);
      expect(result.data[0].id).toBe("w1");
      expect(result.next_cursor).toBe("next-c");
      expect(result.has_more).toBe(true);
      expect(mockPrefsRepo.getWebhooksByPublicKeyPaginated).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "cursor-1",
        10,
      );
    });
  });

  describe("getWebhook", () => {
    it("should return webhook by ID", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(makePref());

      const result = await service.getWebhook("webhook-1");

      expect(result).not.toBeNull();
      expect(result?.id).toBe("webhook-1");
    });

    it("should return null for non-existent webhook", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(null);

      const result = await service.getWebhook("nonexistent");

      expect(result).toBeNull();
    });
  });

  describe("updateWebhook", () => {
    it("should update webhook URL", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(makePref());
      mockPrefsRepo.upsertPreference.mockResolvedValue(
        makePref({ webhookUrl: "https://new.url/webhook" }),
      );

      const result = await service.updateWebhook("webhook-1", PUBLIC_KEY, {
        webhookUrl: "https://new.url/webhook",
      });

      expect(result?.webhookUrl).toBe("https://new.url/webhook");
    });

    it("should return null if webhook not found", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(null);

      const result = await service.updateWebhook("nonexistent", PUBLIC_KEY, {
        webhookUrl: "https://new.url/webhook",
      });

      expect(result).toBeNull();
    });

    it("should return null if webhook belongs to different public key", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(
        makePref({ publicKey: "GDIFFERENT" }),
      );

      const result = await service.updateWebhook("webhook-1", PUBLIC_KEY, {
        webhookUrl: "https://new.url/webhook",
      });

      expect(result).toBeNull();
    });
  });

  describe("deleteWebhook", () => {
    it("should delete existing webhook", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(makePref());
      mockPrefsRepo.deleteWebhook.mockResolvedValue(true);

      const result = await service.deleteWebhook("webhook-1", PUBLIC_KEY);

      expect(result).toBe(true);
      expect(mockPrefsRepo.deleteWebhook).toHaveBeenCalledWith("webhook-1");
    });

    it("should return false for non-existent webhook", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(null);

      const result = await service.deleteWebhook("nonexistent", PUBLIC_KEY);

      expect(result).toBe(false);
      expect(mockPrefsRepo.deleteWebhook).not.toHaveBeenCalled();
    });
  });

  describe("regenerateSecret", () => {
    it("should generate new secret", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(makePref());
      mockPrefsRepo.regenerateWebhookSecret.mockResolvedValue(
        makePref({ webhookSecret: "whsec_newsecret" }),
      );

      const result = await service.regenerateSecret("webhook-1", PUBLIC_KEY);

      expect(result).not.toBeNull();
      expect(result?.secret).toMatch(/^whsec_[a-f0-9]{64}$/);
    });

    it("should return null for non-existent webhook", async () => {
      mockPrefsRepo.getWebhookById.mockResolvedValue(null);

      const result = await service.regenerateSecret("nonexistent", PUBLIC_KEY);

      expect(result).toBeNull();
    });
  });

  describe("getStats", () => {
    it("should return webhook statistics", async () => {
      mockLogRepo.getWebhookStats.mockResolvedValue({
        totalSent: 100,
        totalFailed: 5,
        pendingRetries: 2,
        lastDeliveryAt: "2024-01-15T10:30:00Z",
        lastError: undefined,
      });

      const result = await service.getStats(PUBLIC_KEY);

      expect(result.totalSent).toBe(100);
      expect(result.totalFailed).toBe(5);
      expect(result.pendingRetries).toBe(2);
    });
  });
});
