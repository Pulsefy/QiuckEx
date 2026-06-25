import { HttpException, NotFoundException } from "@nestjs/common";

import { WebhookReplayService } from "../webhook-replay.service";
import { WEBHOOK_MAX_DELIVERY_ATTEMPTS } from "../webhook-retry.constants";

describe("WebhookReplayService", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockLogRepo: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockReplayRepo: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockRetryScheduler: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockAuditService: any;
  let service: WebhookReplayService;

  const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
  const WEBHOOK_ID = "00000000-0000-0000-0000-000000000001";
  const EVENT_TYPE = "payment.received";
  const EVENT_ID = "tx_abc123";

  const baseDelivery = {
    id: "log-1",
    eventType: EVENT_TYPE,
    eventId: EVENT_ID,
    status: "failed",
    attempts: 2,
    lastError: "HTTP 500",
    createdAt: "2024-01-15T10:00:00Z",
    updatedAt: "2024-01-15T10:05:00Z",
  };

  beforeEach(() => {
    mockLogRepo = {
      getWebhookDelivery: jest.fn().mockResolvedValue(baseDelivery),
      resetForManualReplay: jest.fn().mockResolvedValue(undefined),
    };

    mockReplayRepo = {
      createReplayLog: jest.fn().mockResolvedValue({
        id: "replay-1",
        webhookId: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        eventType: EVENT_TYPE,
        eventId: EVENT_ID,
        status: "queued",
        triggeredBy: "api",
        createdAt: "2024-01-15T10:10:00Z",
      }),
      updateReplayLog: jest.fn().mockResolvedValue(undefined),
      getReplayStats: jest.fn().mockResolvedValue({
        replayCount: 1,
        lastReplayAt: "2024-01-15T10:10:00Z",
      }),
      listReplayLogs: jest.fn().mockResolvedValue([]),
    };

    mockRetryScheduler = {
      redeliver: jest.fn().mockResolvedValue(true),
    };

    mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    service = new WebhookReplayService(
      mockLogRepo,
      mockReplayRepo,
      mockRetryScheduler,
      mockAuditService,
    );
    service.resetLimiter();
  });

  describe("getDeliveryStatus", () => {
    it("returns retry schedule and last error for failed deliveries", async () => {
      const status = await service.getDeliveryStatus(
        PUBLIC_KEY,
        EVENT_ID,
        EVENT_TYPE,
      );

      expect(status.eventId).toBe(EVENT_ID);
      expect(status.lastError).toBe("HTTP 500");
      expect(status.maxAttempts).toBe(WEBHOOK_MAX_DELIVERY_ATTEMPTS);
      expect(status.nextRetryAt).toBeDefined();
      expect(status.replayCount).toBe(1);
    });

    it("surfaces DLQ reason when attempts exhausted", async () => {
      mockLogRepo.getWebhookDelivery.mockResolvedValue({
        ...baseDelivery,
        status: "dlq",
        attempts: WEBHOOK_MAX_DELIVERY_ATTEMPTS,
        lastError: "Connection timeout",
      });

      const status = await service.getDeliveryStatus(
        PUBLIC_KEY,
        EVENT_ID,
        EVENT_TYPE,
      );

      expect(status.status).toBe("dlq");
      expect(status.dlqReason).toBe("Connection timeout");
      expect(status.nextRetryAt).toBeUndefined();
    });

    it("throws when delivery not found", async () => {
      mockLogRepo.getWebhookDelivery.mockResolvedValue(null);
      await expect(
        service.getDeliveryStatus(PUBLIC_KEY, EVENT_ID, EVENT_TYPE),
      ).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe("replayDelivery", () => {
    it("replays deterministically and records audit trail", async () => {
      const result = await service.replayDelivery(
        PUBLIC_KEY,
        WEBHOOK_ID,
        EVENT_ID,
        EVENT_TYPE,
      );

      expect(result.queued).toBe(true);
      expect(result.deliverySuccess).toBe(true);
      expect(result.replayId).toBe("replay-1");
      expect(mockLogRepo.resetForManualReplay).toHaveBeenCalledWith(
        PUBLIC_KEY,
        EVENT_TYPE,
        EVENT_ID,
      );
      expect(mockRetryScheduler.redeliver).toHaveBeenCalledWith(
        PUBLIC_KEY,
        EVENT_ID,
        EVENT_TYPE,
      );
      expect(mockAuditService.log).toHaveBeenCalledWith(
        "api",
        "webhook.replay",
        `${EVENT_TYPE}/${EVENT_ID}`,
        expect.objectContaining({ webhookId: WEBHOOK_ID }),
      );
      expect(mockReplayRepo.updateReplayLog).toHaveBeenCalledWith(
        "replay-1",
        expect.objectContaining({ status: "succeeded", deliverySuccess: true }),
      );
    });

    it("rejects replay while delivery is pending (in progress)", async () => {
      mockLogRepo.getWebhookDelivery.mockResolvedValue({
        ...baseDelivery,
        status: "pending",
        attempts: 0,
      });

      await expect(
        service.replayDelivery(PUBLIC_KEY, WEBHOOK_ID, EVENT_ID, EVENT_TYPE),
      ).rejects.toMatchObject({ status: 409 });

      expect(mockRetryScheduler.redeliver).not.toHaveBeenCalled();
    });

    it("enforces per-event cooldown (abuse protection)", async () => {
      await service.replayDelivery(
        PUBLIC_KEY,
        WEBHOOK_ID,
        EVENT_ID,
        EVENT_TYPE,
      );

      await expect(
        service.replayDelivery(PUBLIC_KEY, WEBHOOK_ID, EVENT_ID, EVENT_TYPE),
      ).rejects.toBeInstanceOf(HttpException);

      expect(mockRetryScheduler.redeliver).toHaveBeenCalledTimes(1);
    });

    it("enforces webhook quota across events", async () => {
      process.env["WEBHOOK_REPLAY_QUOTA_PER_HOUR"] = "1";
      process.env["WEBHOOK_REPLAY_EVENT_COOLDOWN_MS"] = "0";
      const quotaService = new WebhookReplayService(
        mockLogRepo,
        mockReplayRepo,
        mockRetryScheduler,
        mockAuditService,
      );

      await quotaService.replayDelivery(
        PUBLIC_KEY,
        WEBHOOK_ID,
        "tx_one",
        EVENT_TYPE,
      );

      mockLogRepo.getWebhookDelivery.mockResolvedValue({
        ...baseDelivery,
        eventId: "tx_two",
      });

      await expect(
        quotaService.replayDelivery(
          PUBLIC_KEY,
          WEBHOOK_ID,
          "tx_two",
          EVENT_TYPE,
        ),
      ).rejects.toMatchObject({ status: 429 });

      delete process.env["WEBHOOK_REPLAY_QUOTA_PER_HOUR"];
      delete process.env["WEBHOOK_REPLAY_EVENT_COOLDOWN_MS"];
    });
  });
});
