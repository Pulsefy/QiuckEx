import { Test, TestingModule } from "@nestjs/testing";
import {
  WebhookDeliveryHandler,
  PermanentJobError,
} from "../webhook-delivery.handler";
import { NotificationLogRepository } from "../../../notifications/notification-log.repository";
import { Job, CancellationToken, JobStatus } from "../../types";
import { WebhookDeliveryPayload } from "../../types/job-payloads.types";

describe("WebhookDeliveryHandler", () => {
  let handler: WebhookDeliveryHandler;
  let logRepo: jest.Mocked<NotificationLogRepository>;
  let mockFetch: jest.SpyInstance;

  const makeJob = (
    overrides: Partial<WebhookDeliveryPayload> = {},
  ): Job<WebhookDeliveryPayload> => ({
    id: "job-1",
    type: "WEBHOOK_DELIVERY" as unknown as Job<WebhookDeliveryPayload>["type"],
    payload: {
      webhookUrl: "https://example.com/webhook",
      eventType: "payment.received",
      eventId: "evt-1",
      recipientPublicKey: "GABCDEF",
      payload: { title: "Payment", body: "You received 10 XLM" },
      ...overrides,
    },
    status: JobStatus.PENDING,
    attempts: 0,
    maxAttempts: 5,
    createdAt: new Date(),
    scheduledAt: new Date(),
    startedAt: null,
    completedAt: null,
    failureReason: null,
    visibilityTimeout: null,
  });

  const cancellationToken: CancellationToken = {
    throwIfCancelled: jest.fn(),
    isCancelled: jest.fn().mockReturnValue(false),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WebhookDeliveryHandler,
        {
          provide: NotificationLogRepository,
          useValue: {
            markSent: jest.fn().mockResolvedValue(undefined),
            markFailed: jest.fn().mockResolvedValue(undefined),
          },
        },
      ],
    }).compile();

    handler = module.get<WebhookDeliveryHandler>(WebhookDeliveryHandler);
    logRepo = module.get(NotificationLogRepository);
    mockFetch = jest.spyOn(global, "fetch");
  });

  afterEach(() => {
    mockFetch.mockRestore();
  });

  // ---------------------------------------------------------------------------
  // execute – success
  // ---------------------------------------------------------------------------
  describe("execute – success", () => {
    it("should send POST and mark as sent on 200", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve("ok"),
      });

      await handler.execute(makeJob(), cancellationToken);

      expect(mockFetch).toHaveBeenCalledWith(
        "https://example.com/webhook",
        expect.objectContaining({ method: "POST" }),
      );
      expect(logRepo.markSent).toHaveBeenCalled();
    });

    it("should include correct headers in the request", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve("ok"),
      });

      await handler.execute(makeJob(), cancellationToken);

      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers).toMatchObject({
        "Content-Type": "application/json",
        "X-QuickEx-Event": "payment.received",
        "X-QuickEx-Event-Id": "evt-1",
      });
    });

    it("should include correlation ID when present", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve("ok"),
      });

      const job = makeJob();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (job.payload as any).correlationId = "corr-123";

      await handler.execute(job, cancellationToken);

      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers["X-QuickEx-Correlation-Id"]).toBe("corr-123");
    });
  });

  // ---------------------------------------------------------------------------
  // execute – transient errors (should throw regular Error)
  // ---------------------------------------------------------------------------
  describe("execute – transient errors", () => {
    it("should throw regular Error on 500 (transient)", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve("Internal Server Error"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(Error);
      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.not.toThrow(PermanentJobError);
    });

    it("should throw regular Error on 503 (transient)", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503,
        text: () => Promise.resolve("Service Unavailable"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(Error);
    });

    it("should throw regular Error on 408 Request Timeout (transient)", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 408,
        text: () => Promise.resolve("Timeout"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(Error);
    });

    it("should throw regular Error on 429 Too Many Requests (transient)", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 429,
        text: () => Promise.resolve("Rate limited"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(Error);
    });

    it("should throw regular Error on network failure", async () => {
      mockFetch.mockRejectedValue(new Error("ECONNREFUSED"));

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(/Network error/);
    });
  });

  // ---------------------------------------------------------------------------
  // execute – permanent errors (should throw PermanentJobError)
  // ---------------------------------------------------------------------------
  describe("execute – permanent errors", () => {
    it("should throw PermanentJobError on 400 Bad Request", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve("Bad Request"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(PermanentJobError);
    });

    it("should throw PermanentJobError on 401 Unauthorized", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        text: () => Promise.resolve("Unauthorized"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(PermanentJobError);
    });

    it("should throw PermanentJobError on 404 Not Found", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        text: () => Promise.resolve("Not Found"),
      });

      await expect(
        handler.execute(makeJob(), cancellationToken),
      ).rejects.toThrow(PermanentJobError);
    });
  });

  // ---------------------------------------------------------------------------
  // validate
  // ---------------------------------------------------------------------------
  describe("validate", () => {
    it("should pass for a valid payload", async () => {
      const payload: WebhookDeliveryPayload = {
        webhookUrl: "https://example.com/hook",
        eventType: "payment.received",
        eventId: "evt-1",
        recipientPublicKey: "GABCDEF",
        payload: { title: "Test" },
      };

      await expect(handler.validate(payload)).resolves.toBeUndefined();
    });

    it("should throw PermanentJobError when webhookUrl is missing", async () => {
      const payload = {
        webhookUrl: "",
        eventType: "payment.received",
        eventId: "evt-1",
        recipientPublicKey: "GABCDEF",
        payload: { title: "Test" },
      };

      await expect(handler.validate(payload)).rejects.toThrow(
        PermanentJobError,
      );
      await expect(handler.validate(payload)).rejects.toThrow(
        /webhookUrl is required/,
      );
    });

    it("should throw PermanentJobError when eventType is missing", async () => {
      const payload = {
        webhookUrl: "https://example.com/hook",
        eventType: "",
        eventId: "evt-1",
        recipientPublicKey: "GABCDEF",
        payload: { title: "Test" },
      };

      await expect(handler.validate(payload)).rejects.toThrow(
        PermanentJobError,
      );
    });

    it("should throw PermanentJobError for invalid URL", async () => {
      const payload = {
        webhookUrl: "not-a-url",
        eventType: "payment.received",
        eventId: "evt-1",
        recipientPublicKey: "GABCDEF",
        payload: { title: "Test" },
      };

      await expect(handler.validate(payload)).rejects.toThrow(
        PermanentJobError,
      );
      await expect(handler.validate(payload)).rejects.toThrow(
        /Invalid webhook URL/,
      );
    });

    it("should throw PermanentJobError when recipientPublicKey is missing", async () => {
      const payload = {
        webhookUrl: "https://example.com/hook",
        eventType: "payment.received",
        eventId: "evt-1",
        recipientPublicKey: "",
        payload: { title: "Test" },
      };

      await expect(handler.validate(payload)).rejects.toThrow(
        PermanentJobError,
      );
    });

    it("should throw PermanentJobError when payload object is missing", async () => {
      const payload = {
        webhookUrl: "https://example.com/hook",
        eventType: "payment.received",
        eventId: "evt-1",
        recipientPublicKey: "GABCDEF",
        payload: null as unknown as WebhookDeliveryPayload["payload"],
      };

      await expect(handler.validate(payload)).rejects.toThrow(
        PermanentJobError,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // onFailure
  // ---------------------------------------------------------------------------
  describe("onFailure", () => {
    it("should log failure to notification log", async () => {
      const job = makeJob();
      const error = new Error("Delivery timed out");

      await handler.onFailure(job, error);

      expect(logRepo.markFailed).toHaveBeenCalledWith(
        "GABCDEF",
        "webhook",
        "payment.received",
        "evt-1",
        "Delivery timed out",
      );
    });

    it("should not throw if logging fails", async () => {
      logRepo.markFailed.mockRejectedValue(new Error("DB down"));

      const job = makeJob();
      await expect(
        handler.onFailure(job, new Error("err")),
      ).resolves.toBeUndefined();
    });
  });
});
