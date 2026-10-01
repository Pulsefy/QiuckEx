// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  categoryForEventType,
  fetchNotifications,
  mapInAppNotification,
  markAllNotificationsRead,
  markNotificationRead,
} from "./notificationsApi";

const originalFetch = global.fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

beforeEach(() => {
  vi.stubEnv("NEXT_PUBLIC_QUICKEX_API_URL", "http://localhost:mock");
  global.fetch = vi.fn();
});

afterEach(() => {
  global.fetch = originalFetch;
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("categoryForEventType", () => {
  it("maps payment and escrow event types to their categories", () => {
    expect(categoryForEventType("payment.received")).toBe("payments");
    expect(categoryForEventType("escrow.outbid")).toBe("escrows");
  });

  it("falls back to system for unknown event types", () => {
    expect(categoryForEventType("webhook.retry")).toBe("system");
  });
});

describe("mapInAppNotification", () => {
  it("maps a backend notification into the stored shape", () => {
    const mapped = mapInAppNotification({
      id: "n1",
      publicKey: "GAAA",
      eventType: "payment.received",
      eventId: "e1",
      title: "Payment received",
      body: "You received 10 USDC",
      read: false,
      metadata: { href: "/dashboard?tx=abc", actionLabel: "Open transaction" },
      createdAt: "2026-04-23T09:24:00.000Z",
    });

    expect(mapped).toMatchObject({
      id: "n1",
      category: "payments",
      title: "Payment received",
      description: "You received 10 USDC",
      href: "/dashboard?tx=abc",
      actionLabel: "Open transaction",
      readAt: null,
    });
  });

  it("marks read notifications with a readAt timestamp", () => {
    const mapped = mapInAppNotification({
      id: "n2",
      publicKey: "GAAA",
      eventType: "system.notice",
      eventId: "e2",
      title: "Notice",
      body: "Body",
      read: true,
      createdAt: "2026-04-22T09:24:00.000Z",
    });

    expect(mapped.category).toBe("system");
    expect(mapped.readAt).toBe("2026-04-22T09:24:00.000Z");
    expect(mapped.href).toBe("/notifications");
  });
});

describe("fetchNotifications", () => {
  it("fetches live notifications from the backend endpoint", async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse([
        {
          id: "n1",
          publicKey: "GAAA",
          eventType: "payment.received",
          eventId: "e1",
          title: "Payment received",
          body: "Body",
          read: false,
          createdAt: "2026-04-23T09:24:00.000Z",
        },
      ]),
    );

    const result = await fetchNotifications();

    expect(result.degraded).toBe(false);
    expect(result.notifications).toHaveLength(1);
    expect(result.notifications[0].id).toBe("n1");

    const calledUrl = (global.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as string;
    expect(calledUrl).toContain("/notifications/in-app");
  });

  it("returns a degraded empty list when the backend fails", async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("network down"),
    );

    const result = await fetchNotifications();

    expect(result.degraded).toBe(true);
    expect(result.notifications).toEqual([]);
  });

  it("returns a degraded empty list on a server error response", async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({ message: "boom" }, 500),
    );

    const result = await fetchNotifications();

    expect(result.degraded).toBe(true);
    expect(result.notifications).toEqual([]);
  });
});

describe("mark read actions", () => {
  it("posts a single mark-as-read request", async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({}, 204),
    );

    await markNotificationRead("n1");

    const [url, init] = (global.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    expect(url).toContain("/notifications/in-app/n1/read");
    expect(init.method).toBe("POST");
  });

  it("posts a mark-all-as-read request", async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({}, 204),
    );

    await markAllNotificationsRead();

    const [url, init] = (global.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    expect(url).toContain("/notifications/in-app/read-all");
    expect(init.method).toBe("POST");
  });

  it("rejects when the backend call fails", async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({ message: "nope" }, 500),
    );

    await expect(markNotificationRead("n1")).rejects.toThrow("nope");
  });
});
