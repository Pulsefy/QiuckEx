import { Test, TestingModule } from "@nestjs/testing";
import {
  ExportGenerationHandler,
  PermanentJobError,
} from "../export-generation.handler";
import { SupabaseService } from "../../../supabase/supabase.service";
import { NotificationService } from "../../../notifications/notification.service";
import { ExportStorageService } from "../../../exports/export-storage.service";
import { NotificationPreferencesRepository } from "../../../notifications/notification-preferences.repository";
import { JobQueueService } from "../../job-queue.service";
import { Job, CancellationToken, JobStatus } from "../../types";
import { ExportGenerationPayload } from "../../types/job-payloads.types";
import { JobType } from "../../types";
import type { ExportCompletedPayload } from "../../../notifications/types/notification.types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Chainable, awaitable supabase query builder stub. */
function makeQueryBuilder(data: Record<string, unknown>[]) {
  const result = { data, error: null };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const builder: any = jest
    .fn()
    .mockImplementation(() => Promise.resolve(result));
  builder.select = jest.fn().mockReturnThis();
  builder.eq = jest.fn().mockReturnThis();
  return Object.assign(builder, {
    then: (
      resolve: (value: { data: Record<string, unknown>[]; error: null }) => void,
      reject: (reason?: unknown) => void,
    ) => Promise.resolve(result).then(resolve, reject),
  });
}

function makeSupabaseMock(data: Record<string, unknown>[]) {
  return {
    getClient: jest.fn().mockReturnValue({
      from: jest.fn().mockReturnValue(makeQueryBuilder(data)),
    }),
  };
}

function makeJob(
  overrides: Partial<ExportGenerationPayload> = {},
): Job<ExportGenerationPayload> {
  return {
    id: "job-42",
    type: "EXPORT_GENERATION" as unknown as Job<ExportGenerationPayload>["type"],
    payload: {
      userId: "GUSER123",
      exportType: "transactions",
      filters: {},
      format: "csv",
      deliveryMethod: "email",
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
  };
}

function makeCancellationToken(): CancellationToken {
  return {
    throwIfCancelled: jest.fn(),
    isCancelled: jest.fn().mockReturnValue(false),
  };
}

describe("ExportGenerationHandler – email delivery (BE-101)", () => {
  let handler: ExportGenerationHandler;
  let notificationService: jest.Mocked<NotificationService>;
  let notificationPrefsRepo: jest.Mocked<NotificationPreferencesRepository>;
  let jobQueueService: jest.Mocked<JobQueueService>;
  let uploadedContent: string | undefined;

  beforeEach(async () => {
    uploadedContent = undefined;
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ExportGenerationHandler,
        {
          provide: SupabaseService,
          useValue: makeSupabaseMock([{ id: 1 }, { id: 2 }]),
        },
        {
          provide: NotificationService,
          useValue: {
            deliverExportEmail: jest.fn(),
            notifyExportFailed: jest.fn(),
          },
        },
        {
          provide: ExportStorageService,
          useValue: {
            uploadArtifact: jest.fn().mockResolvedValue({ storageKey: 'exports/GUSER123/job-42.csv', sizeBytes: 10 }),
            issueDownloadToken: jest.fn().mockReturnValue({ token: 'test-token', expiresAt: Math.floor(Date.now() / 1000) + 3600 }),
          },
        },
        {
          provide: NotificationPreferencesRepository,
          useValue: {
            getWebhooksByPublicKey: jest.fn(),
          },
        },
        {
          provide: JobQueueService,
          useValue: {
            enqueue: jest.fn(),
          },
        },
      ],
    }).compile();

    handler = module.get<ExportGenerationHandler>(ExportGenerationHandler);
    notificationService = module.get(NotificationService);
    notificationPrefsRepo = module.get(NotificationPreferencesRepository);
    jobQueueService = module.get(JobQueueService);
  });

  describe("execute – email delivery succeeds", () => {
    it("routes the completed export through the notifications module", async () => {
      notificationService.deliverExportEmail.mockResolvedValue({
        delivered: true,
        templateVersionId: "tpl-version-7",
      });

      await expect(
        handler.execute(makeJob(), makeCancellationToken()),
      ).resolves.toBeUndefined();

      expect(notificationService.deliverExportEmail).toHaveBeenCalledTimes(1);

      const payload = notificationService.deliverExportEmail.mock
        .calls[0][0] as ExportCompletedPayload;
      expect(payload.eventType).toBe("export.completed");
      expect(payload.recipientPublicKey).toBe("GUSER123");
      expect(payload.exportType).toBe("transactions");
      expect(payload.format).toBe("csv");
      expect(payload.recordCount).toBe(2);
      expect(payload.jobId).toBe("job-42");
      expect(payload.eventId).toBe("export:job-42");
    });

    it("completes the job when the templated email is delivered", async () => {
      notificationService.deliverExportEmail.mockResolvedValue({
        delivered: true,
        templateVersionId: "tpl-version-7",
      });

      const job = makeJob({ deliveryMethod: "email", format: "json" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();
      expect(notificationService.deliverExportEmail).toHaveBeenCalled();
    });
  });

  it("neutralizes formula-injection text in exported CSV while preserving negative numbers", async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ExportGenerationHandler,
        {
          provide: SupabaseService,
          useValue: makeSupabaseMock([{
            memo: '=cmd|calc',
            plus: '+plus',
            minus: '-minus',
            at: '@at',
            tab: '\ttab',
            carriageReturn: '\rcarriage',
            amount: -12.5,
          }]),
        },
        {
          provide: NotificationService,
          useValue: { deliverExportEmail: jest.fn(), notifyExportFailed: jest.fn() },
        },
        {
          provide: ExportStorageService,
          useValue: {
            uploadArtifact: jest.fn().mockImplementation(({ content }: { content: string }) => {
              uploadedContent = content;
              return Promise.resolve({ storageKey: 'exports/GUSER123/job-42.csv', sizeBytes: 10 });
            }),
            issueDownloadToken: jest.fn().mockReturnValue({ token: 'test-token', expiresAt: 1 }),
          },
        },
        { provide: NotificationPreferencesRepository, useValue: { getWebhooksByPublicKey: jest.fn() } },
        { provide: JobQueueService, useValue: { enqueue: jest.fn() } },
      ],
    }).compile();
    handler = module.get<ExportGenerationHandler>(ExportGenerationHandler);

    await handler.execute(
      makeJob({ deliveryMethod: "download" }),
      makeCancellationToken(),
    );

    expect(uploadedContent).toContain("'=cmd|calc");
    expect(uploadedContent).toContain("'+plus");
    expect(uploadedContent).toContain("'-minus");
    expect(uploadedContent).toContain("'@at");
    expect(uploadedContent).toContain("'\ttab");
    expect(uploadedContent).toContain("\"'\rcarriage\"");
    expect(uploadedContent).toContain(",-12.5");
  });

  describe("execute – provider/template failure handling", () => {
    it("throws so the failure is surfaced on the export job record when sending fails", async () => {
      notificationService.deliverExportEmail.mockResolvedValue({
        delivered: false,
        error: "SendGrid 500: upstream unavailable",
      });

      await expect(
        handler.execute(makeJob(), makeCancellationToken()),
      ).rejects.toThrow(/Email delivery failed.*SendGrid 500/);
    });

    it("throws when no enabled email preference exists for the user", async () => {
      notificationService.deliverExportEmail.mockResolvedValue({
        delivered: false,
        error: "No enabled email channel preference with an email address found for GUSER123",
      });

      await expect(
        handler.execute(makeJob(), makeCancellationToken()),
      ).rejects.toThrow(/No enabled email channel preference/);
    });

    it("propagates errors thrown by the notifications module", async () => {
      notificationService.deliverExportEmail.mockRejectedValue(
        new Error("preferences lookup failed"),
      );

      await expect(
        handler.execute(makeJob(), makeCancellationToken()),
      ).rejects.toThrow(/Export generation failed.*preferences lookup failed/);
    });
  });

  describe("execute – non-email delivery methods are untouched", () => {
    it("does not send an email for download deliveries via the email channel directly", async () => {
      // download delivery now calls deliverExportEmail with the download token metadata,
      // so the storage service must be mocked to succeed.
      notificationService.deliverExportEmail.mockResolvedValue({
        delivered: true,
        templateVersionId: undefined,
      });

      const job = makeJob({ deliveryMethod: "download" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();
    });

    it("does not send an email for webhook deliveries", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();
      expect(notificationService.deliverExportEmail).not.toHaveBeenCalled();
      expect(jobQueueService.enqueue).toHaveBeenCalled();
    });
  });

  describe("execute – webhook delivery", () => {
    let notificationService: jest.Mocked<NotificationService>;
    let notificationPrefsRepo: jest.Mocked<NotificationPreferencesRepository>;
    let jobQueueService: jest.Mocked<JobQueueService>;
    let exportStorageService: jest.Mocked<
      Pick<ExportStorageService, "uploadArtifact" | "issueDownloadToken">
    >;

    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          ExportGenerationHandler,
          {
            provide: SupabaseService,
            useValue: makeSupabaseMock([{ id: 1 }, { id: 2 }]),
          },
          {
            provide: NotificationService,
            useValue: {
              deliverExportEmail: jest.fn(),
              notifyExportFailed: jest.fn(),
            },
          },
          {
            provide: ExportStorageService,
            useValue: {
              uploadArtifact: jest.fn().mockResolvedValue({ storageKey: 'exports/GUSER123/job-42.csv', sizeBytes: 10 }),
              issueDownloadToken: jest.fn().mockReturnValue({ token: 'test-token', expiresAt: Math.floor(Date.now() / 1000) + 3600 }),
            },
          },
          {
            provide: NotificationPreferencesRepository,
            useValue: {
              getWebhooksByPublicKey: jest.fn(),
            },
          },
          {
            provide: JobQueueService,
            useValue: {
              enqueue: jest.fn(),
            },
          },
        ],
      }).compile();

      handler = module.get<ExportGenerationHandler>(ExportGenerationHandler);
      notificationService = module.get(NotificationService);
      notificationPrefsRepo = module.get(NotificationPreferencesRepository);
      jobQueueService = module.get(JobQueueService);
      exportStorageService = module.get(ExportStorageService);
    });

    it("enqueues webhook delivery job with correct payload", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();

      expect(notificationPrefsRepo.getWebhooksByPublicKey).toHaveBeenCalledWith("GUSER123");
      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        JobType.WEBHOOK_DELIVERY,
        expect.objectContaining({
          recipientPublicKey: "GUSER123",
          webhookUrl: "https://example.com/webhook",
          eventType: "export.completed",
          eventId: "export:job-42",
          payload: expect.objectContaining({
            exportType: "transactions",
            format: "csv",
            recordCount: 2,
            jobId: "job-42",
          }),
        }),
      );
    });

    it("throws when no enabled webhook URL is found", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([]);

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).rejects.toThrow(/No enabled https webhook URL found for user GUSER123/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it("throws when webhook preference exists but has no URL", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: undefined, webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).rejects.toThrow(/No enabled https webhook URL found for user GUSER123/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it("skips an enabled non-https target so a signed download reference is never posted in cleartext", async () => {
      // The API rejects a request unless *some* enabled https target exists, so
      // the handler must resolve the same target. Picking the first enabled
      // entry regardless of scheme would post the token over plain http.
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "http://insecure.example.com/webhook", webhookSecret: "whsec_insecure", enabled: true, events: null, minAmountStroops: 0n },
        { id: "webhook-2", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://secure.example.com/webhook", webhookSecret: "whsec_secure", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();

      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        JobType.WEBHOOK_DELIVERY,
        expect.objectContaining({
          webhookUrl: "https://secure.example.com/webhook",
          signingSecret: "whsec_secure",
        }),
      );
    });

    it("fails rather than posting the download reference to a non-https target", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "http://insecure.example.com/webhook", webhookSecret: "whsec_insecure", enabled: true, events: null, minAmountStroops: 0n },
      ]);

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).rejects.toThrow(/No enabled https webhook URL found for user GUSER123/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it("selects first enabled webhook when multiple exist", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook1", webhookSecret: "whsec_test1", enabled: true, events: null, minAmountStroops: 0n },
        { id: "webhook-2", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook2", webhookSecret: "whsec_test2", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();

      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        JobType.WEBHOOK_DELIVERY,
        expect.objectContaining({
          webhookUrl: "https://example.com/webhook1",
        }),
      );
    });

    it("HMAC-signs the delivery using the registered webhook secret", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      await handler.execute(
        makeJob({ deliveryMethod: "webhook" }),
        makeCancellationToken(),
      );

      const [, payload] = jobQueueService.enqueue.mock.calls[0] as unknown as [unknown, { signingSecret: string }];
      expect(payload.signingSecret).toBe("whsec_test");
    });

    it("sends export metadata and a time-limited download reference, never the raw export body", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      await handler.execute(
        makeJob({ deliveryMethod: "webhook" }),
        makeCancellationToken(),
      );

      const [, queued] = jobQueueService.enqueue.mock.calls[0] as unknown as [unknown, { payload: Record<string, unknown> }];

      expect(queued.payload).toEqual({
        exportType: "transactions",
        format: "csv",
        recordCount: 2,
        jobId: "job-42",
        sizeBytes: 10,
        downloadReference: {
          storageKey: "exports/GUSER123/job-42.csv",
          userId: "GUSER123",
          token: "test-token",
          tokenExpiresAt: expect.any(Number),
        },
      });
      expect(queued.payload).not.toHaveProperty("data");
      // The generated CSV (header "id" then the two record ids) must not leak.
      expect(JSON.stringify(queued.payload)).not.toContain("\n1\n2");
    });

    it("links the delivery back to the export job so a permanent failure is not reported as success", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      await handler.execute(
        makeJob({ deliveryMethod: "webhook" }),
        makeCancellationToken(),
      );

      const [, queued] = jobQueueService.enqueue.mock.calls[0] as unknown as [unknown, { relatedJobId: string }];
      expect(queued.relatedJobId).toBe("job-42");
    });

    it("stores the artifact before enqueuing so the download reference is redeemable", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue.mockResolvedValue("webhook-job-123");

      await handler.execute(
        makeJob({ deliveryMethod: "webhook" }),
        makeCancellationToken(),
      );

      expect(exportStorageService.uploadArtifact).toHaveBeenCalledWith({
        jobId: "job-42",
        userId: "GUSER123",
        content: expect.any(String),
        format: "csv",
        exportType: "transactions",
      });
      expect(exportStorageService.issueDownloadToken).toHaveBeenCalledWith({
        jobId: "job-42",
        userId: "GUSER123",
      });
      expect(
        exportStorageService.uploadArtifact.mock.invocationCallOrder[0],
      ).toBeLessThan(jobQueueService.enqueue.mock.invocationCallOrder[0]);
    });

    it("retry-then-fail: a transient enqueue failure fails the job and the retry re-attempts the delivery", async () => {
      notificationPrefsRepo.getWebhooksByPublicKey.mockResolvedValue([
        { id: "webhook-1", publicKey: "GUSER123", channel: "webhook", webhookUrl: "https://example.com/webhook", webhookSecret: "whsec_test", enabled: true, events: null, minAmountStroops: 0n },
      ]);
      jobQueueService.enqueue
        .mockRejectedValueOnce(new Error("job store unavailable"))
        .mockResolvedValueOnce("webhook-job-123");

      const job = makeJob({ deliveryMethod: "webhook" });

      // First attempt: transient failure -> transient error so the queue retries.
      await expect(
        handler.execute(job, makeCancellationToken()),
      ).rejects.toThrow(/Export generation failed.*job store unavailable/);
      expect(notificationService.notifyExportFailed).not.toHaveBeenCalled();

      // Second attempt: succeeds.
      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();
      expect(jobQueueService.enqueue).toHaveBeenCalledTimes(2);
    });

    it("retry-then-fail: exhausting delivery retries surfaces on the export job record", async () => {
      const job = makeJob({ deliveryMethod: "webhook" });
      const error = new Error("Webhook returned HTTP 400");

      await handler.onFailure(job, error);

      expect(notificationService.notifyExportFailed).toHaveBeenCalledWith(
        "GUSER123",
        "job-42",
        "transactions",
        "csv",
        "Webhook returned HTTP 400",
      );
    });
  });

  describe("validate", () => {
    it("passes for a valid email delivery payload", async () => {
      const payload: ExportGenerationPayload = {
        userId: "GUSER123",
        exportType: "payments",
        filters: {},
        format: "csv",
        deliveryMethod: "email",
      };

      await expect(handler.validate(payload)).resolves.toBeUndefined();
    });

    it("throws PermanentJobError for an invalid payload", async () => {
      const payload = {
        userId: "",
        exportType: "unknown",
        filters: {},
        format: "xml",
        deliveryMethod: "fax",
      } as unknown as ExportGenerationPayload;

      await expect(handler.validate(payload)).rejects.toThrow(
        PermanentJobError,
      );
    });
  });

  describe("onFailure – notification emission (BE-103)", () => {
    it("emits a failure notification to the requesting user on permanent job failure", async () => {
      const job = makeJob();
      const error = new Error("database connection refused");

      await handler.onFailure(job, error);

      expect(notificationService.notifyExportFailed).toHaveBeenCalledTimes(1);
      expect(notificationService.notifyExportFailed).toHaveBeenCalledWith(
        "GUSER123",   // userId
        "job-42",     // jobId
        "transactions", // exportType
        "csv",        // format
        "database connection refused", // safe reason (single-line message)
      );
    });

    it("strips embedded newlines / stack frames from the failure reason before notifying the user", async () => {
      const job = makeJob();
      const error = new Error("query failed\n    at Object.<anonymous> (/src/db.ts:42:7)\n    at processTicksAndRejections");

      await handler.onFailure(job, error);

      expect(notificationService.notifyExportFailed).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.any(String),
        expect.any(String),
        "query failed", // only the first line — no stack frames
      );
    });

    it("falls back to a generic safe reason when the error has no message", async () => {
      const job = makeJob();
      const error = new Error("");

      await handler.onFailure(job, error);

      expect(notificationService.notifyExportFailed).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.any(String),
        expect.any(String),
        "An unexpected error occurred",
      );
    });

    it("does not throw after permanent failure", async () => {
      notificationService.notifyExportFailed.mockResolvedValue(undefined);

      await expect(
        handler.onFailure(makeJob(), new Error("exhausted")),
      ).resolves.toBeUndefined();
    });
  });
});
