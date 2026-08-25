import { Test, TestingModule } from "@nestjs/testing";
import {
  ExportGenerationHandler,
  PermanentJobError,
} from "../export-generation.handler";
import { SupabaseService } from "../../../supabase/supabase.service";
import { NotificationService } from "../../../notifications/notification.service";
import { Job, CancellationToken, JobStatus } from "../../types";
import { ExportGenerationPayload } from "../../types/job-payloads.types";
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
          },
        },
      ],
    }).compile();

    handler = module.get<ExportGenerationHandler>(ExportGenerationHandler);
    notificationService = module.get(NotificationService);
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
    it("does not send an email for download deliveries", async () => {
      const job = makeJob({ deliveryMethod: "download" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();
      expect(notificationService.deliverExportEmail).not.toHaveBeenCalled();
    });

    it("does not send an email for webhook deliveries", async () => {
      const job = makeJob({ deliveryMethod: "webhook" });

      await expect(
        handler.execute(job, makeCancellationToken()),
      ).resolves.toBeUndefined();
      expect(notificationService.deliverExportEmail).not.toHaveBeenCalled();
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

  describe("onFailure", () => {
    it("does not throw after permanent failure", async () => {
      await expect(
        handler.onFailure(makeJob(), new Error("exhausted")),
      ).resolves.toBeUndefined();
    });
  });
});
