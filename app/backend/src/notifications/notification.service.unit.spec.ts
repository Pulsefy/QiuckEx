import { Test, TestingModule } from "@nestjs/testing";
import { EventEmitterModule, EventEmitter2 } from "@nestjs/event-emitter";
import { NotificationService } from "./notification.service";
import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { NotificationLogRepository } from "./notification-log.repository";
import { NOTIFICATION_PROVIDERS } from "./providers/notification-provider.interface";

describe("NotificationService (Event Hook Verification)", () => {
  let service: NotificationService;
  let eventEmitter: EventEmitter2;
  let module: TestingModule;

  const mockPrefsRepo = {
    getEnabledPreferences: jest.fn().mockResolvedValue([]),
    upsertPreference: jest.fn(),
    disableChannel: jest.fn(),
  };

  const mockLogRepo = {
    createPending: jest.fn().mockResolvedValue("log-id"),
    markSent: jest.fn().mockResolvedValue(undefined),
    markFailed: jest.fn().mockResolvedValue(undefined),
    isAlreadySent: jest.fn().mockResolvedValue(false),
    getPendingRetries: jest.fn().mockResolvedValue([]),
  };

  const mockLogger = {
    log: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    module = await Test.createTestingModule({
      imports: [EventEmitterModule.forRoot({ wildcard: true, delimiter: "." })],
      providers: [
        NotificationService,
        { provide: NotificationPreferencesRepository, useValue: mockPrefsRepo },
        { provide: NotificationLogRepository, useValue: mockLogRepo },
        { provide: NOTIFICATION_PROVIDERS, useValue: [] },
      ],
    }).compile();

    await module.init();

    service = module.get<NotificationService>(NotificationService);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);

    Object.defineProperty(service, "logger", {
      value: mockLogger,
      writable: true,
    });
  });

  afterEach(async () => {
    if (module) await module.close();
  });

  it('should react to "username.claimed" event and call dispatch', async () => {
    const dispatchSpy = jest
      .spyOn(NotificationService.prototype, "dispatch")
      .mockResolvedValue(undefined);

    const payload = {
      username: "test_user",
      publicKey: "GD5DJQDZBZJK5JOGKFYRZP66KJ62GON5QMLSLVWSH2VYJ5P2HYHUQRI5",
    };

    await eventEmitter.emitAsync("username.claimed", payload);

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: "username.claimed" }),
    );
    dispatchSpy.mockRestore();
  });

  it('should react to "payment.received" event and call dispatch', async () => {
    const dispatchSpy = jest
      .spyOn(NotificationService.prototype, "dispatch")
      .mockResolvedValue(undefined);

    const payload = {
      txHash: "0xabc123",
      amount: "100000000",
      sender: "GSENDER",
      recipientPublicKey:
        "GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2",
    };

    await eventEmitter.emitAsync("payment.received", payload);

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: "payment.received" }),
    );
    dispatchSpy.mockRestore();
  });
});
