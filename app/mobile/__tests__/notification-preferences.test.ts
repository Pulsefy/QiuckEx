import { Keypair } from "stellar-sdk";
import {
  createSignatureHeaders,
  registerNotificationPreference,
} from "../services/notification-preferences";

describe("Mobile Notification Preferences Service", () => {
  const keypair = Keypair.random();
  const signer = {
    publicKey: keypair.publicKey(),
    sign: (data: Buffer) => keypair.sign(data),
  };

  beforeEach(() => {
    (global as any).fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it("generates valid signature headers", () => {
    const timestamp = 1700000000000;
    const headers = createSignatureHeaders(
      "PUT",
      `/notifications/preferences/${signer.publicKey}`,
      signer,
      timestamp,
    );

    expect(headers["x-timestamp"]).toBe("1700000000000");
    expect(headers["x-public-key"]).toBe(signer.publicKey);
    expect(headers["x-signature"]).toBeDefined();
    expect(typeof headers["x-signature"]).toBe("string");
  });

  it("calls fetch with signed headers when registering preference", async () => {
    const mockResponse = {
      id: "pref-1",
      publicKey: signer.publicKey,
      channel: "push",
      pushToken: "ExponentPushToken[xyz]",
      enabled: true,
    };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockResolvedValue(mockResponse),
    });

    const result = await registerNotificationPreference(
      "http://localhost:3000",
      signer,
      {
        channel: "push",
        pushToken: "ExponentPushToken[xyz]",
        enabled: true,
      },
    );

    expect((global as any).fetch).toHaveBeenCalledWith(
      `http://localhost:3000/notifications/preferences/${signer.publicKey}`,
      expect.objectContaining({
        method: "PUT",
        headers: expect.objectContaining({
          "x-signature": expect.any(String),
          "x-timestamp": expect.any(String),
          "x-public-key": signer.publicKey,
        }),
      }),
    );
    expect(result.channel).toBe("push");
  });

  it("throws error when backend responds with non-2xx status", async () => {
    (global as any).fetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
    });

    await expect(
      registerNotificationPreference("http://localhost:3000", signer, {
        channel: "email",
        email: "test@example.com",
        enabled: true,
      }),
    ).rejects.toThrow("Failed to update notification preference: 401 Unauthorized");
  });
});
