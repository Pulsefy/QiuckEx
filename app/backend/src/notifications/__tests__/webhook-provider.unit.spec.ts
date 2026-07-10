import { WebhookProvider } from "../providers/notification-provider.interface";
import * as crypto from "crypto";
import type {
  NotificationPreference,
  BaseNotificationPayload,
} from "../types/notification.types";

const mockFetch = jest.fn();
global.fetch = mockFetch;

describe("WebhookProvider", () => {
  const provider = new WebhookProvider();

  const PUBLIC_KEY = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
  const WEBHOOK_URL = "https://example.com/webhook";
  const WEBHOOK_SECRET = "whsec_testsecret123";

  function makePref(
    overrides: Partial<NotificationPreference> = {},
  ): NotificationPreference {
    return {
      id: "p1",
      publicKey: PUBLIC_KEY,
      channel: "webhook",
      webhookUrl: WEBHOOK_URL,
      webhookSecret: WEBHOOK_SECRET,
      events: null,
      minAmountStroops: 0n,
      enabled: true,
      ...overrides,
    };
  }

  function makePayload(): BaseNotificationPayload {
    return {
      eventType: "payment.received",
      eventId: "tx-123",
      recipientPublicKey: PUBLIC_KEY,
      title: "Payment Received",
      body: "You received 10 XLM",
      occurredAt: "2024-01-15T10:30:00Z",
      metadata: { amount: "100000000" },
    };
  }

  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe("send", () => {
    it("should send POST request with signed payload", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => '{"received":true}',
      });

      const result = await provider.send(makePref(), makePayload());

      expect(mockFetch).toHaveBeenCalledWith(
        WEBHOOK_URL,
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            "X-QuickEx-Event": "payment.received",
          }),
        }),
      );

      expect(result.httpStatus).toBe(200);
      expect(result.responseBody).toBe('{"received":true}');
    });

    it("should include HMAC signature in header", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => "OK",
      });

      await provider.send(makePref(), makePayload());

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers;
      const signature = headers["X-QuickEx-Signature"];

      expect(signature).toMatch(/^sha256=[a-f0-9]{64}$/);
    });

    it("should send without signature when no secret configured", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => "OK",
      });

      await provider.send(
        makePref({ webhookSecret: undefined }),
        makePayload(),
      );

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers;
      const signature = headers["X-QuickEx-Signature"];

      expect(signature).toBe("");
    });

    it("should throw error for missing webhook URL", async () => {
      await expect(
        provider.send(makePref({ webhookUrl: undefined }), makePayload()),
      ).rejects.toThrow("No webhook URL configured");
    });

    it("should throw error for non-2xx response", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: async () => "Internal Server Error",
      });

      await expect(provider.send(makePref(), makePayload())).rejects.toThrow(
        "Webhook returned HTTP 500",
      );
    });

    it("should include delivery ID and timestamp headers", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => "OK",
      });

      await provider.send(makePref(), makePayload());

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers;

      expect(headers["X-QuickEx-Delivery"]).toMatch(/^wh_\d+_[a-z0-9]+$/);
      expect(headers["X-QuickEx-Timestamp"]).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
      );
    });

    it("should truncate long response bodies", async () => {
      const longBody = "x".repeat(2000);
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => longBody,
      });

      const result = await provider.send(makePref(), makePayload());

      expect(result.responseBody?.length).toBeLessThan(longBody.length);
      expect(result.responseBody).toMatch(/\.\.\.$/);
    });

    it("should handle response body read errors", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => {
          throw new Error("Read error");
        },
      });

      const result = await provider.send(makePref(), makePayload());

      expect(result.httpStatus).toBe(200);
      expect(result.responseBody).toBeUndefined();
    });
  });

  describe("verifySignature", () => {
    it("should verify valid signature", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => "OK",
      });

      await provider.send(makePref(), makePayload());

      const call = mockFetch.mock.calls[0];
      const body = call[1].body;
      const headers = call[1].headers;
      const signature = headers["X-QuickEx-Signature"];
      const timestamp = headers["X-QuickEx-Timestamp"];

      const isValid = WebhookProvider.verifySignature(
        body,
        signature,
        timestamp,
        WEBHOOK_SECRET,
      );
      expect(isValid).toBe(true);
    });

    it("should reject invalid signature", () => {
      const body = JSON.stringify({ test: "data" });
      const timestamp = new Date().toISOString();
      const wrongSecret = "wrong_secret";
      const hmac = crypto.createHmac("sha256", wrongSecret);
      hmac.update(`${timestamp}.${body}`);
      const signature = `sha256=${hmac.digest("hex")}`;

      const isValid = WebhookProvider.verifySignature(
        body,
        signature,
        timestamp,
        WEBHOOK_SECRET,
      );
      expect(isValid).toBe(false);
    });

    it("should reject signature without sha256 prefix", () => {
      const body = JSON.stringify({ test: "data" });
      const timestamp = new Date().toISOString();
      const signature = "invalid";

      const isValid = WebhookProvider.verifySignature(
        body,
        signature,
        timestamp,
        WEBHOOK_SECRET,
      );
      expect(isValid).toBe(false);
    });
  });

  describe("verifySignatureDetailed", () => {
    function sign(body: string, timestamp: string, secret: string): string {
      const hmac = crypto.createHmac("sha256", secret);
      hmac.update(`${timestamp}.${body}`);
      return `sha256=${hmac.digest("hex")}`;
    }

    it("returns VALID for a correctly signed payload", () => {
      const body = JSON.stringify({ eventType: "payment.received" });
      const timestamp = new Date().toISOString();
      const signature = sign(body, timestamp, WEBHOOK_SECRET);

      const result = WebhookProvider.verifySignatureDetailed(
        body,
        signature,
        timestamp,
        WEBHOOK_SECRET,
      );
      expect(result).toEqual({ valid: true, reason: "VALID" });
    });

    it("returns MISSING_FIELDS when any required field is empty", () => {
      expect(
        WebhookProvider.verifySignatureDetailed("", "sha256=abc", "ts", "secret"),
      ).toEqual({ valid: false, reason: "MISSING_FIELDS" });
      expect(
        WebhookProvider.verifySignatureDetailed("body", "", "ts", "secret"),
      ).toEqual({ valid: false, reason: "MISSING_FIELDS" });
    });

    it("returns INVALID_SIGNATURE_FORMAT when the signature lacks the sha256= prefix", () => {
      const body = "{}";
      const timestamp = new Date().toISOString();

      const result = WebhookProvider.verifySignatureDetailed(
        body,
        "not-a-real-signature",
        timestamp,
        WEBHOOK_SECRET,
      );
      expect(result).toEqual({ valid: false, reason: "INVALID_SIGNATURE_FORMAT" });
    });

    it("returns INVALID_TIMESTAMP for an unparseable timestamp", () => {
      const body = "{}";
      const signature = sign(body, "not-a-date", WEBHOOK_SECRET);

      const result = WebhookProvider.verifySignatureDetailed(
        body,
        signature,
        "not-a-date",
        WEBHOOK_SECRET,
      );
      expect(result).toEqual({ valid: false, reason: "INVALID_TIMESTAMP" });
    });

    it("returns TIMESTAMP_OUT_OF_TOLERANCE for a stale timestamp", () => {
      const body = "{}";
      const staleTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      const signature = sign(body, staleTimestamp, WEBHOOK_SECRET);

      const result = WebhookProvider.verifySignatureDetailed(
        body,
        signature,
        staleTimestamp,
        WEBHOOK_SECRET,
      );
      expect(result).toEqual({ valid: false, reason: "TIMESTAMP_OUT_OF_TOLERANCE" });
    });

    it("returns SIGNATURE_MISMATCH when the digest doesn't match", () => {
      const body = "{}";
      const timestamp = new Date().toISOString();
      const signature = sign(body, timestamp, "a-different-secret");

      const result = WebhookProvider.verifySignatureDetailed(
        body,
        signature,
        timestamp,
        WEBHOOK_SECRET,
      );
      expect(result).toEqual({ valid: false, reason: "SIGNATURE_MISMATCH" });
    });
  });
});
