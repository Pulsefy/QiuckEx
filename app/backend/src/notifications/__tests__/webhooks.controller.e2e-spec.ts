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
      getStats: jest.fn().mockResolvedValue({
        totalSent: 0,
        totalFailed: 0,
        pendingRetries: 0,
      }),
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
});
