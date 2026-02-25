import {
  SendGridEmailProvider,
  ExpoPushProvider,
  WebhookProvider,
} from "../providers/notification-provider.interface";
import type {
  NotificationPreference,
  BaseNotificationPayload,
} from "../types/notification.types";

const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

function makePref(
  overrides: Partial<NotificationPreference> = {},
): NotificationPreference {
  return {
    id: "p1",
    publicKey: PUBLIC_KEY,
    channel: "email",
    email: "user@example.com",
    events: null,
    minAmountStroops: 0n,
    enabled: true,
    ...overrides,
  };
}

function makePayload(): BaseNotificationPayload {
  return {
    eventType: "payment.received",
    eventId: "tx-1",
    recipientPublicKey: PUBLIC_KEY,
    title: "Payment",
    body: "You received XLM",
    occurredAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Mock global fetch
// ---------------------------------------------------------------------------

const mockFetch = jest.fn();
global.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
});

// ---------------------------------------------------------------------------

describe("SendGridEmailProvider", () => {
  const provider = new SendGridEmailProvider(
    "SG.test-key",
    "noreply@quickex.to",
  );

  it("throws when no email on preference", async () => {
    await expect(
      provider.send(makePref({ email: undefined }), makePayload()),
    ).rejects.toThrow("No email address configured");
  });

  it("sends a POST to SendGrid and returns messageId", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      headers: { get: () => "msg-sendgrid-1" },
    });

    const result = await provider.send(makePref(), makePayload());
    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.sendgrid.com/v3/mail/send",
      expect.objectContaining({ method: "POST" }),
    );
    expect(result.messageId).toBe("msg-sendgrid-1");
  });

  it("throws on non-2xx response", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "Unauthorized",
    });

    await expect(provider.send(makePref(), makePayload())).rejects.toThrow(
      "SendGrid error 401",
    );
  });
});

describe("ExpoPushProvider", () => {
  const provider = new ExpoPushProvider();

  it("throws when no pushToken on preference", async () => {
    await expect(
      provider.send(
        makePref({ channel: "push", pushToken: undefined }),
        makePayload(),
      ),
    ).rejects.toThrow("No push token configured");
  });

  it("sends to Expo API and returns messageId", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ data: { id: "expo-msg-1" } }),
    });

    const result = await provider.send(
      makePref({ channel: "push", pushToken: "ExponentPushToken[abc123]" }),
      makePayload(),
    );

    expect(mockFetch).toHaveBeenCalledWith(
      "https://exp.host/--/api/v2/push/send",
      expect.objectContaining({ method: "POST" }),
    );
    expect(result.messageId).toBe("expo-msg-1");
  });
});

describe("WebhookProvider", () => {
  const provider = new WebhookProvider();

  it("throws when no webhookUrl on preference", async () => {
    await expect(
      provider.send(
        makePref({ channel: "webhook", webhookUrl: undefined }),
        makePayload(),
      ),
    ).rejects.toThrow("No webhook URL configured");
  });

  it("POSTs the payload to the configured URL", async () => {
    mockFetch.mockResolvedValue({ ok: true });

    await provider.send(
      makePref({ channel: "webhook", webhookUrl: "https://example.com/hook" }),
      makePayload(),
    );

    expect(mockFetch).toHaveBeenCalledWith(
      "https://example.com/hook",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("throws on non-2xx response", async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 503 });

    await expect(
      provider.send(
        makePref({
          channel: "webhook",
          webhookUrl: "https://example.com/hook",
        }),
        makePayload(),
      ),
    ).rejects.toThrow("HTTP 503");
  });
});
