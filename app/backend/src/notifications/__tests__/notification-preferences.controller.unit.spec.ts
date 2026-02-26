import { Test, TestingModule } from "@nestjs/testing";
import { NotificationPreferencesController } from "../notification-preferences.controller";
import { NotificationPreferencesRepository } from "../notification-preferences.repository";
import type { NotificationPreference } from "../types/notification.types";

const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

function makePref(
  overrides: Partial<NotificationPreference> = {},
): NotificationPreference {
  return {
    id: "pref-uuid-1",
    publicKey: PUBLIC_KEY,
    channel: "email",
    email: "user@example.com",
    events: null,
    minAmountStroops: 0n,
    enabled: true,
    ...overrides,
  };
}

const mockRepo = (): jest.Mocked<NotificationPreferencesRepository> =>
  ({
    getEnabledPreferences: jest.fn().mockResolvedValue([makePref()]),
    upsertPreference: jest.fn().mockResolvedValue(makePref()),
    disableChannel: jest.fn().mockResolvedValue(undefined),
  }) as unknown as jest.Mocked<NotificationPreferencesRepository>;

describe("NotificationPreferencesController", () => {
  let controller: NotificationPreferencesController;
  let repo: jest.Mocked<NotificationPreferencesRepository>;

  beforeEach(async () => {
    repo = mockRepo();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [NotificationPreferencesController],
      providers: [
        { provide: NotificationPreferencesRepository, useValue: repo },
      ],
    }).compile();

    controller = module.get(NotificationPreferencesController);
  });

  describe("listPreferences", () => {
    it("returns serialised preferences for a public key", async () => {
      const result = await controller.listPreferences(PUBLIC_KEY);
      expect(repo.getEnabledPreferences).toHaveBeenCalledWith(PUBLIC_KEY);
      expect(result).toHaveLength(1);
      expect(result[0].channel).toBe("email");
      // bigint is serialised as string
      expect(result[0].minAmountStroops).toBe("0");
    });
  });

  describe("upsertPreference", () => {
    it("calls upsertPreference on repo and returns dto", async () => {
      repo.upsertPreference.mockResolvedValue(
        makePref({ channel: "push", pushToken: "ExponentPushToken[abc]" }),
      );

      const result = await controller.upsertPreference(PUBLIC_KEY, {
        channel: "push",
        pushToken: "ExponentPushToken[abc]",
        enabled: true,
      });

      expect(repo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "push",
        expect.objectContaining({ pushToken: "ExponentPushToken[abc]" }),
      );
      expect(result.channel).toBe("push");
    });

    it("converts minAmountStroops number to bigint before saving", async () => {
      await controller.upsertPreference(PUBLIC_KEY, {
        channel: "email",
        email: "user@example.com",
        minAmountStroops: 100_000_000,
      });

      expect(repo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "email",
        expect.objectContaining({ minAmountStroops: 100_000_000n }),
      );
    });

    it("passes null events when not provided (match all)", async () => {
      await controller.upsertPreference(PUBLIC_KEY, {
        channel: "email",
        email: "user@example.com",
      });

      expect(repo.upsertPreference).toHaveBeenCalledWith(
        PUBLIC_KEY,
        "email",
        expect.objectContaining({ events: null }),
      );
    });
  });

  describe("disableChannel", () => {
    it("calls disableChannel on the repo", async () => {
      await controller.disableChannel(PUBLIC_KEY, "email");
      expect(repo.disableChannel).toHaveBeenCalledWith(PUBLIC_KEY, "email");
    });
  });
});
