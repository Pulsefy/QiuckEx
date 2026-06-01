/* eslint-disable @typescript-eslint/ban-ts-comment */
// @ts-nocheck
import { beforeEach, describe, expect, it, vi } from "vitest";
import { errorReporter, redactPII } from "@/lib/errorReporter";

describe("errorReporter", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    process.env.NEXT_PUBLIC_ERROR_REPORTING_ENABLED = "false";
    process.env.NEXT_PUBLIC_ERROR_REPORTING_URL = "";
    process.env.NEXT_PUBLIC_APP_VERSION = "test-version";
    process.env.NEXT_PUBLIC_VERCEL_ENV = "preview";
    global.fetch = vi.fn();
  });

  it("redacts email, phone, and card patterns", () => {
    const payload = {
      email: "alice@example.com",
      phone: "+1 (555) 123-4567",
      card: "4111 1111 1111 1111",
      nested: {
        note: "Contact bob@work-mail.com or 555-987-6543.",
      },
    };

    const redacted = redactPII(payload) as Record<string, unknown>;

    expect(redacted.email).toBe("[REDACTED_EMAIL]");
    expect(redacted.phone).toBe("[REDACTED_PHONE]");
    expect(redacted.card).toBe("[REDACTED_CARD]");
    expect(
      (redacted.nested as Record<string, unknown>).note
    ).toContain("[REDACTED_EMAIL]");
    expect(
      (redacted.nested as Record<string, unknown>).note
    ).toContain("[REDACTED_PHONE]");
  });

  it("does not send when reporting is disabled", async () => {
    process.env.NEXT_PUBLIC_ERROR_REPORTING_ENABLED = "false";
    await errorReporter.captureError(new Error("test"));
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("sends payload when reporting is enabled", async () => {
    process.env.NEXT_PUBLIC_ERROR_REPORTING_ENABLED = "true";
    process.env.NEXT_PUBLIC_ERROR_REPORTING_URL = "https://example.com/api/errors";
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    global.fetch = mockFetch as unknown as typeof fetch;

    await errorReporter.captureError(new Error("Server failed to load"), {
      requestId: "req-123",
      correlationId: "corr-456",
      userId: "user-789",
      route: "/dashboard",
      componentStack: "at Dashboard (Dashboard.tsx:10)",
      extra: { feature: "payment" },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe("https://example.com/api/errors");
    expect(options).toMatchObject({
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    });

    const body = JSON.parse(options.body as string);
    expect(body).toHaveProperty("timestamp");
    expect(body.error.message).toBe("Server failed to load");
    expect(body.context.requestId).toBe("req-123");
    expect(body.context.correlationId).toBe("corr-456");
    expect(body.appVersion).toBe("test-version");
    expect(body.environment).toBe("preview");
  });
});
