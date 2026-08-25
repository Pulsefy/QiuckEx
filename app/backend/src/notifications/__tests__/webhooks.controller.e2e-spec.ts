import { Test, TestingModule } from "@nestjs/testing";
import { INestApplication, ValidationPipe } from "@nestjs/common";
import * as request from "supertest";
import { WebhooksController } from "../webhooks.controller";
import { WebhookService } from "../webhook.service";

describe("WebhooksController (e2e)", () => {
  let app: INestApplication;
  let mockWebhookService: Partial<WebhookService>;

  const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
  const WEBHOOK_ID = "00000000-0000-0000-0000-000000000001";

  beforeAll(async () => {
    mockWebhookService = {
      createWebhook: jest.fn().mockResolvedValue({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "whsec_testsecret",
        events: null,
        minAmountStroops: "0",
        enabled: true,
        createdAt: "2024-01-15T10:00:00Z",
        updatedAt: "2024-01-15T10:00:00Z",
      }),
      listWebhooks: jest.fn().mockResolvedValue([]),
      getWebhook: jest.fn().mockResolvedValue(null),
      updateWebhook: jest.fn().mockResolvedValue(null),
      deleteWebhook: jest.fn().mockResolvedValue(false),
      regenerateSecret: jest.fn().mockResolvedValue(null),
      getDeliveryLogs: jest.fn().mockResolvedValue([]),
      getDeliveryHistory: jest.fn().mockResolvedValue({ data: [], next_cursor: null, has_more: false }),
      getDeliveryDetail: jest.fn().mockResolvedValue(null),
      getStats: jest.fn().mockResolvedValue({
        totalSent: 0,
        totalFailed: 0,
        pendingRetries: 0,
      }),
      redeliverEvent: jest.fn().mockResolvedValue({
        queued: true,
        deliverySuccess: true,
        message: "Event redelivery triggered successfully",
      }),
      getDeliveryStatus: jest.fn(),
      getReplayHistory: jest.fn().mockResolvedValue([]),
    };

    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [WebhooksController],
      providers: [
        {
          provide: WebhookService,
          useValue: mockWebhookService,
        },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
        forbidNonWhitelisted: true,
      }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe("POST /webhooks/:publicKey", () => {
    it("should create a webhook", () => {
      return request(app.getHttpServer())
        .post(`/webhooks/${PUBLIC_KEY}`)
        .send({
          webhookUrl: "https://example.com/webhook",
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.id).toBe(WEBHOOK_ID);
          expect(res.body.webhookUrl).toBe("https://example.com/webhook");
          expect(res.body.secret).toMatch(/^whsec_/);
        });
    });

    it("should reject invalid webhook URL", () => {
      return request(app.getHttpServer())
        .post(`/webhooks/${PUBLIC_KEY}`)
        .send({
          webhookUrl: "not-a-valid-url",
        })
        .expect(400);
    });

    it("should accept custom secret", () => {
      (mockWebhookService.createWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "my-custom-secret",
        events: null,
        minAmountStroops: "0",
        enabled: true,
        createdAt: "2024-01-15T10:00:00Z",
        updatedAt: "2024-01-15T10:00:00Z",
      });

      return request(app.getHttpServer())
        .post(`/webhooks/${PUBLIC_KEY}`)
        .send({
          webhookUrl: "https://example.com/webhook",
          secret: "my-custom-secret",
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.secret).toBe("my-custom-secret");
        });
    });
  });

  describe("GET /webhooks/:publicKey", () => {
    it("should list webhooks", () => {
      (mockWebhookService.listWebhooks as jest.Mock).mockResolvedValueOnce([
        {
          id: WEBHOOK_ID,
          publicKey: PUBLIC_KEY,
          webhookUrl: "https://example.com/webhook",
          secret: "whsec_test",
          events: null,
          minAmountStroops: "0",
          enabled: true,
        },
      ]);

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}`)
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
          expect(res.body).toHaveLength(1);
        });
    });
  });

  describe("GET /webhooks/:publicKey/:id", () => {
    it("should return webhook details", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "whsec_test",
        events: null,
        minAmountStroops: "0",
        enabled: true,
      });

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.id).toBe(WEBHOOK_ID);
        });
    });

    it("should return 404 for non-existent webhook", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce(null);

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/nonexistent`)
        .expect(404);
    });
  });

  describe("PUT /webhooks/:publicKey/:id", () => {
    it("should update webhook", () => {
      (mockWebhookService.updateWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://new-url.com/webhook",
        secret: "whsec_test",
        events: ["payment.received"],
        minAmountStroops: "100000000",
        enabled: true,
      });

      return request(app.getHttpServer())
        .put(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}`)
        .send({
          webhookUrl: "https://new-url.com/webhook",
          events: ["payment.received"],
          minAmountStroops: 100000000,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.webhookUrl).toBe("https://new-url.com/webhook");
        });
    });
  });

  describe("DELETE /webhooks/:publicKey/:id", () => {
    it("should delete webhook", () => {
      (mockWebhookService.deleteWebhook as jest.Mock).mockResolvedValueOnce(
        true,
      );

      return request(app.getHttpServer())
        .delete(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}`)
        .expect(204);
    });

    it("should return 404 for non-existent webhook", () => {
      (mockWebhookService.deleteWebhook as jest.Mock).mockResolvedValueOnce(
        false,
      );

      return request(app.getHttpServer())
        .delete(`/webhooks/${PUBLIC_KEY}/nonexistent`)
        .expect(404);
    });
  });

  describe("POST /webhooks/:publicKey/:id/regenerate-secret", () => {
    it("should regenerate secret", () => {
      (mockWebhookService.regenerateSecret as jest.Mock).mockResolvedValueOnce({
        secret: "whsec_newsecret123",
      });

      return request(app.getHttpServer())
        .post(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}/regenerate-secret`)
        .expect(200)
        .expect((res) => {
          expect(res.body.secret).toBe("whsec_newsecret123");
        });
    });
  });

  describe("GET /webhooks/:publicKey/:id/stats", () => {
    it("should return webhook statistics", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "whsec_test",
        events: null,
        minAmountStroops: "0",
        enabled: true,
      });
      (mockWebhookService.getStats as jest.Mock).mockResolvedValueOnce({
        totalSent: 100,
        totalFailed: 5,
        pendingRetries: 2,
        lastDeliveryAt: "2024-01-15T10:30:00Z",
      });

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}/stats`)
        .expect(200)
        .expect((res) => {
          expect(res.body.totalSent).toBe(100);
          expect(res.body.totalFailed).toBe(5);
        });
    });
  });

  describe("POST /webhooks/:publicKey/:id/redeliver", () => {
    it("should trigger redelivery of a specific event", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "whsec_test",
        events: null,
        minAmountStroops: "0",
        enabled: true,
      });
      (mockWebhookService.redeliverEvent as jest.Mock).mockResolvedValueOnce({
        queued: true,
        deliverySuccess: true,
        message: "Event redelivery triggered successfully",
        replayId: "replay-1",
      });

      return request(app.getHttpServer())
        .post(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}/redeliver`)
        .send({ eventId: "tx_abc123", eventType: "payment.received" })
        .expect(200)
        .expect((res) => {
          expect(res.body.queued).toBe(true);
          expect(res.body.replayId).toBe("replay-1");
        });
    });

    it("should return 404 if webhook not found for redeliver", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce(null);

      return request(app.getHttpServer())
        .post(`/webhooks/${PUBLIC_KEY}/nonexistent/redeliver`)
        .send({ eventId: "tx_abc123", eventType: "payment.received" })
        .expect(404);
    });
  });

  describe("GET /webhooks/:publicKey/:id/deliveries/:eventType/:eventId", () => {
    it("should return delivery status with retry visibility", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "whsec_test",
        events: null,
        minAmountStroops: "0",
        enabled: true,
      });
      (mockWebhookService.getDeliveryStatus as jest.Mock).mockResolvedValueOnce({
        eventId: "tx_abc123",
        eventType: "payment.received",
        status: "failed",
        attempts: 2,
        maxAttempts: 5,
        lastError: "HTTP 500",
        nextRetryAt: "2024-01-15T10:06:00Z",
        createdAt: "2024-01-15T10:00:00Z",
        updatedAt: "2024-01-15T10:05:00Z",
        replayCount: 0,
      });

      return request(app.getHttpServer())
        .get(
          `/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}/deliveries/payment.received/tx_abc123`,
        )
        .expect(200)
        .expect((res) => {
          expect(res.body.lastError).toBe("HTTP 500");
          expect(res.body.nextRetryAt).toBeDefined();
        });
    });
  });

  describe("GET /webhooks/:publicKey/:id/replays", () => {
    it("should return replay audit history", () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValueOnce({
        id: WEBHOOK_ID,
        publicKey: PUBLIC_KEY,
        webhookUrl: "https://example.com/webhook",
        secret: "whsec_test",
        events: null,
        minAmountStroops: "0",
        enabled: true,
      });
      (mockWebhookService.getReplayHistory as jest.Mock).mockResolvedValueOnce([
        {
          id: "replay-1",
          eventType: "payment.received",
          eventId: "tx_abc123",
          status: "succeeded",
          triggeredBy: "api",
          deliverySuccess: true,
          createdAt: "2024-01-15T10:10:00Z",
        },
      ]);

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/${WEBHOOK_ID}/replays`)
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveLength(1);
          expect(res.body[0].status).toBe("succeeded");
        });
    });
  });

  describe("GET /webhooks/:publicKey/history and /deliveries", () => {
    it("should return delivery history with status and eventType filters", () => {
      (mockWebhookService.getDeliveryHistory as jest.Mock).mockResolvedValueOnce({
        data: [
          {
            id: "log-1",
            webhookId: WEBHOOK_ID,
            endpointUrl: "https://example.com/webhook",
            eventType: "payment.received",
            eventId: "tx-100",
            status: "failed",
            attempts: 2,
            lastError: "HTTP 500 whsec_••••••••",
            createdAt: "2024-01-15T10:00:00Z",
            payloadMetadata: { event_id: "tx-100", secret: "••••••••" },
          },
        ],
        next_cursor: "cursor-token",
        has_more: true,
      });

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/history?status=failed&eventType=payment.received&limit=10`)
        .expect(200)
        .expect((res) => {
          expect(res.body.data).toHaveLength(1);
          expect(res.body.data[0].status).toBe("failed");
          expect(res.body.data[0].lastError).toContain("whsec_••••••••");
          expect(res.body.next_cursor).toBe("cursor-token");
          expect(res.body.has_more).toBe(true);
        });
    });

    it("should support /deliveries alias endpoint", () => {
      (mockWebhookService.getDeliveryHistory as jest.Mock).mockResolvedValueOnce({
        data: [
          {
            id: "log-2",
            eventType: "EscrowDeposited",
            eventId: "escrow-200",
            status: "sent",
            attempts: 1,
            createdAt: "2024-01-15T11:00:00Z",
          },
        ],
        next_cursor: null,
        has_more: false,
      });

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/deliveries`)
        .expect(200)
        .expect((res) => {
          expect(res.body.data).toHaveLength(1);
          expect(res.body.data[0].status).toBe("sent");
          expect(res.body.has_more).toBe(false);
        });
    });
  });

  describe("GET /webhooks/:publicKey/deliveries/:logId", () => {
    it("should return detailed delivery attempt log", () => {
      (mockWebhookService.getDeliveryDetail as jest.Mock).mockResolvedValueOnce({
        id: "log-1",
        webhookId: WEBHOOK_ID,
        endpointUrl: "https://example.com/webhook",
        eventType: "payment.received",
        eventId: "tx-100",
        status: "dlq",
        attempts: 3,
        maxAttempts: 3,
        lastError: "HTTP 503 Service Unavailable",
        dlqReason: "HTTP 503 Service Unavailable",
        createdAt: "2024-01-15T10:00:00Z",
        attemptHistory: [
          { attemptNumber: 1, status: "retried", timestamp: "2024-01-15T10:00:00Z" },
          { attemptNumber: 2, status: "retried", timestamp: "2024-01-15T10:01:00Z" },
          { attemptNumber: 3, status: "dlq", error: "HTTP 503 Service Unavailable", timestamp: "2024-01-15T10:05:00Z" },
        ],
      });

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/deliveries/log-1`)
        .expect(200)
        .expect((res) => {
          expect(res.body.id).toBe("log-1");
          expect(res.body.status).toBe("dlq");
          expect(res.body.attemptHistory).toHaveLength(3);
        });
    });

    it("should return 404 for non-existent delivery log ID", () => {
      (mockWebhookService.getDeliveryDetail as jest.Mock).mockResolvedValueOnce(null);

      return request(app.getHttpServer())
        .get(`/webhooks/${PUBLIC_KEY}/deliveries/non-existent-log`)
        .expect(404);
    });
  });
});
