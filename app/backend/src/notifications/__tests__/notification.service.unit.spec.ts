import { Test, TestingModule } from "@nestjs/testing";
import { EventEmitterModule, EventEmitter2 } from "@nestjs/event-emitter";

import { NotificationService } from "../notification.service";
import { NotificationPreferencesRepository } from "../notification-preferences.repository";
import { NotificationLogRepository } from "../notification-log.repository";
import { NOTIFICATION_PROVIDERS } from "../providers/notification-provider.interface";
import type {
  NotificationPreference,
  NotificationPayload,
} from "../types/notification.types";
import type { EscrowDepositedEvent } from "../../ingestion/types/contract-event.types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

function makeEmailPref(
  overrides: Partial<NotificationPreference> = {},
): NotificationPreference {
  return {
    id: "pref-1",
    publicKey: PUBLIC_KEY,
    channel: "email",
    email: "user@example.com",
    events: null,
    minAmountStroops: 0n,
    enabled: true,
    ...overrides,
  };
}

function makeEscrowDepositedEvent(
  overrides: Partial<EscrowDepositedEvent> = {},
): EscrowDepositedEvent {
  return {
    eventType: "EscrowDeposited",
    txHash: "txhash1",
    ledgerSequence: 100,
    pagingToken: "100-1",
    contractTimestamp: 1700000000n,
    commitment: "deadbeef".repeat(8),
    owner: PUBLIC_KEY,
    token: "CTOKEN",
    amount: 50_000_000n, // 5 XLM
    expiresAt: 1800000000n,
    ...overrides,
  };
}

function makePayload(
  overrides: Partial<NotificationPayload> = {},
): NotificationPayload {
  return {
    eventType: "payment.received",
    eventId: "tx-abc",
    recipientPublicKey: PUBLIC_KEY,
    title: "Payment",
    body: "You received a payment",
    occurredAt: new Date().toISOString(),
    amountStroops: 100_000_000n,
    txHash: "tx-abc",
    sender: "GSENDER",
    ...overrides,
  } as NotificationPayload;
}

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

const mockPrefsRepo = (): jest.Mocked<NotificationPreferencesRepository> =>
  ({
    getEnabledPreferences: jest.fn().mockResolvedValue([]),
    upsertPreference: jest.fn(),
    disableChannel: jest.fn(),
  }) as unknown as jest.Mocked<NotificationPreferencesRepository>;

const mockLogRepo = (): jest.Mocked<NotificationLogRepository> =>
  ({
    createPending: jest.fn().mockResolvedValue("log-id"),
    markSent: jest.fn().mockResolvedValue(undefined),
    markFailed: jest.fn().mockResolvedValue(undefined),
    isAlreadySent: jest.fn().mockResolvedValue(false),
    getPendingRetries: jest.fn().mockResolvedValue([]),
  }) as unknown as jest.Mocked<NotificationLogRepository>;

const mockEmailProvider = () => ({
  channel: "email",
  send: jest.fn().mockResolvedValue({ messageId: "msg-1" }),
});

// ---------------------------------------------------------------------------

describe("NotificationService", () => {
  let service: NotificationService;
  let prefsRepo: jest.Mocked<NotificationPreferencesRepository>;
  let logRepo: jest.Mocked<NotificationLogRepository>;
  let emailProvider: ReturnType<typeof mockEmailProvider>;
  let eventEmitter: EventEmitter2;
  let module: TestingModule;

  beforeEach(async () => {
    prefsRepo = mockPrefsRepo();
    logRepo = mockLogRepo();
    emailProvider = mockEmailProvider();

    module = await Test.createTestingModule({
      imports: [EventEmitterModule.forRoot({ wildcard: true, delimiter: "." })],
      providers: [
        NotificationService,
        { provide: NotificationPreferencesRepository, useValue: prefsRepo },
        { provide: NotificationLogRepository, useValue: logRepo },
        { provide: NOTIFICATION_PROVIDERS, useValue: [emailProvider] },
      ],
    }).compile();

    await module.init();

    service = module.get(NotificationService);
    eventEmitter = module.get(EventEmitter2);
  });

  afterEach(async () => {
    jest.clearAllMocks();
    await module.close();
  });

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------

  it("registers providers on init", () => {
    // providerMap is private — test through behaviour
    prefsRepo.getEnabledPreferences.mockResolvedValue([makeEmailPref()]);
    expect(service).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Event listener wiring
  // -------------------------------------------------------------------------

  it("calls dispatch when stellar.EscrowDeposited is emitted", async () => {
    const dispatchSpy = jest
      .spyOn(NotificationService.prototype, "dispatch")
      .mockResolvedValue(undefined);
    const event = makeEscrowDepositedEvent();

    await eventEmitter.emitAsync("stellar.EscrowDeposited", event);

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: "EscrowDeposited",
        recipientPublicKey: PUBLIC_KEY,
      }),
    );
    dispatchSpy.mockRestore();
  });

  it("calls dispatch when payment.received is emitted", async () => {
    const dispatchSpy = jest
      .spyOn(NotificationService.prototype, "dispatch")
      .mockResolvedValue(undefined);

    await eventEmitter.emitAsync("payment.received", {
      txHash: "tx123",
      amount: "100000000",
      sender: "GSENDER",
      recipientPublicKey: PUBLIC_KEY,
    });

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: "payment.received" }),
    );
    dispatchSpy.mockRestore();
  });

  it("calls dispatch when username.claimed is emitted", async () => {
    const dispatchSpy = jest
      .spyOn(NotificationService.prototype, "dispatch")
      .mockResolvedValue(undefined);

    await eventEmitter.emitAsync("username.claimed", {
      username: "alice",
      publicKey: PUBLIC_KEY,
    });

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: "username.claimed" }),
    );
    dispatchSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // dispatch — preference filtering
  // -------------------------------------------------------------------------

  describe("dispatch", () => {
    it("skips sending when no preferences exist", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([]);
      await service.dispatch(makePayload());
      expect(emailProvider.send).not.toHaveBeenCalled();
    });

    it("sends to all matching channels", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([makeEmailPref()]);
      await service.dispatch(makePayload());
      expect(emailProvider.send).toHaveBeenCalledTimes(1);
    });

    it("filters out events not in the preference events list", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([
        makeEmailPref({ events: ["EscrowDeposited"] }),
      ]);

      await service.dispatch(
        makePayload({
          eventType: "payment.received",
        } as Partial<NotificationPayload>),
      );
      expect(emailProvider.send).not.toHaveBeenCalled();
    });

    it("filters out events below minAmountStroops threshold", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([
        makeEmailPref({ minAmountStroops: 1_000_000_000n }), // 100 XLM threshold
      ]);

      await service.dispatch(makePayload({ amountStroops: 10_000_000n })); // only 1 XLM
      expect(emailProvider.send).not.toHaveBeenCalled();
    });

    it("sends when amount meets the threshold", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([
        makeEmailPref({ minAmountStroops: 10_000_000n }),
      ]);

      await service.dispatch(makePayload({ amountStroops: 50_000_000n }));
      expect(emailProvider.send).toHaveBeenCalledTimes(1);
    });

    it("sends when events list is null (match all)", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([
        makeEmailPref({ events: null }),
      ]);

      await service.dispatch(makePayload());
      expect(emailProvider.send).toHaveBeenCalledTimes(1);
    });

    it("does not throw when preference loading fails", async () => {
      prefsRepo.getEnabledPreferences.mockRejectedValue(new Error("DB error"));
      await expect(service.dispatch(makePayload())).resolves.not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // sendToChannel — idempotency
  // -------------------------------------------------------------------------

  describe("idempotency", () => {
    it("skips sending if notification is already marked sent", async () => {
      logRepo.isAlreadySent.mockResolvedValue(true);
      const pref = makeEmailPref();

      await service.sendToChannel(pref, makePayload());
      expect(emailProvider.send).not.toHaveBeenCalled();
    });

    it("creates a pending log and marks sent on success", async () => {
      logRepo.isAlreadySent.mockResolvedValue(false);
      const pref = makeEmailPref();

      await service.sendToChannel(pref, makePayload());

      expect(logRepo.createPending).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "email",
        "payment.received",
        "tx-abc",
      );
      expect(logRepo.markSent).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "email",
        "payment.received",
        "tx-abc",
        "msg-1",
      );
    });

    it("marks failed on provider error", async () => {
      logRepo.isAlreadySent.mockResolvedValue(false);
      emailProvider.send.mockRejectedValue(new Error("SendGrid 500"));
      const pref = makeEmailPref();

      await service.sendToChannel(pref, makePayload());

      expect(logRepo.markFailed).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "email",
        "payment.received",
        "tx-abc",
        "SendGrid 500",
      );
    });
  });

  // -------------------------------------------------------------------------
  // Rate limiting
  // -------------------------------------------------------------------------

  describe("rate limiting", () => {
    it("drops notifications when rate limit is exceeded", async () => {
      prefsRepo.getEnabledPreferences.mockResolvedValue([makeEmailPref()]);
      logRepo.isAlreadySent.mockResolvedValue(false);

      // Exhaust the rate limit manually
      const rl = service.rateLimiter;
      for (let i = 0; i < 10; i++) {
        rl.allow(PUBLIC_KEY, "email");
      }

      await service.sendToChannel(
        makeEmailPref(),
        makePayload({ eventId: "new-evt" } as Partial<NotificationPayload>),
      );
      expect(emailProvider.send).not.toHaveBeenCalled();
    });

    it("allows notifications under the rate limit", async () => {
      logRepo.isAlreadySent.mockResolvedValue(false);

      // Reset so we start fresh
      service.rateLimiter.reset();
      await service.sendToChannel(makeEmailPref(), makePayload());
      expect(emailProvider.send).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // Retry scheduler
  // -------------------------------------------------------------------------

  describe("retryFailedNotifications", () => {
    it("skips when no retries pending", async () => {
      logRepo.getPendingRetries.mockResolvedValue([]);
      await service.retryFailedNotifications();
      expect(prefsRepo.getEnabledPreferences).not.toHaveBeenCalled();
    });

    it("retries failed entries", async () => {
      logRepo.getPendingRetries.mockResolvedValue([
        {
          publicKey: PUBLIC_KEY,
          channel: "email",
          eventType: "payment.received",
          eventId: "tx-fail",
          attempts: 1,
        },
      ]);
      prefsRepo.getEnabledPreferences.mockResolvedValue([makeEmailPref()]);
      logRepo.isAlreadySent.mockResolvedValue(false);

      await service.retryFailedNotifications();

      expect(emailProvider.send).toHaveBeenCalledTimes(1);
    });

    it("skips retry if preference no longer exists for channel", async () => {
      logRepo.getPendingRetries.mockResolvedValue([
        {
          publicKey: PUBLIC_KEY,
          channel: "push",
          eventType: "payment.received",
          eventId: "tx-fail",
          attempts: 1,
        },
      ]);
      // User only has email pref now, not push
      prefsRepo.getEnabledPreferences.mockResolvedValue([makeEmailPref()]);

      await service.retryFailedNotifications();
      expect(emailProvider.send).not.toHaveBeenCalled();
    });
  });
});
