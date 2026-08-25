import {
  countUnreadInAppNotifications,
  fetchInAppNotifications,
  markAllInAppNotificationsRead,
  markInAppNotificationRead,
} from "../services/in-app-notifications";
import {
  mapInAppNotification,
  mergeNotificationReadState,
} from "../services/notifications";
import type { Notification } from "../types/notification";

jest.mock("../src/config/build", () => ({
  API_URL: "http://localhost:4000",
  APP_VERSION: "1.0.0",
  BUILD_NUMBER: "1",
  BUILD_METADATA: "1.0.0+1",
  BUILD_TAG: "",
  APP_ENVIRONMENT: "dev",
  STELLAR_NETWORK: "testnet",
  IS_DEBUG_BUILD: true,
}));

const API_BASE = "http://localhost:4000";

describe("in-app notifications API client", () => {
  const fetchMock = jest.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  it("fetches in-app notifications with publicKey query", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          data: [
            {
              id: "n1",
              publicKey: "GABC",
              eventType: "payment.received",
              eventId: "tx-1",
              title: "Payment received",
              body: "You received 10 XLM",
              read: false,
              createdAt: "2026-07-26T10:00:00.000Z",
            },
          ],
        }),
    });

    const result = await fetchInAppNotifications("GABC", { page: 1, limit: 20 });

    expect(fetchMock).toHaveBeenCalledWith(
      `${API_BASE}/notifications/in-app?publicKey=GABC&page=1&limit=20`,
      expect.objectContaining({
        headers: expect.objectContaining({ Accept: "application/json" }),
      }),
    );
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("n1");
  });

  it("posts mark-read for a single notification", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });

    await markInAppNotificationRead("notif-42");

    expect(fetchMock).toHaveBeenCalledWith(
      `${API_BASE}/notifications/in-app/notif-42/read`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("posts mark-all-read with publicKey", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });

    await markAllInAppNotificationsRead("GABC");

    expect(fetchMock).toHaveBeenCalledWith(
      `${API_BASE}/notifications/in-app/read-all?publicKey=GABC`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("counts unread notifications for badge refresh", () => {
    expect(
      countUnreadInAppNotifications([
        { read: false },
        { read: true },
        { read: false },
      ]),
    ).toBe(2);
  });
});

describe("notification read-state merge", () => {
  it("maps backend in-app notifications into inbox model", () => {
    const mapped = mapInAppNotification({
      id: "uuid-1",
      publicKey: "GABC",
      eventType: "EscrowDeposited",
      eventId: "escrow-1",
      title: "Escrow funded",
      body: "Funds locked",
      read: false,
      metadata: { commitment: "c1", amount: "5" },
      createdAt: "2026-07-26T12:00:00.000Z",
    });

    expect(mapped).toMatchObject({
      id: "uuid-1",
      title: "Escrow funded",
      message: "Funds locked",
      type: "escrow",
      read: false,
      data: {
        escrowId: "c1",
        amount: "5",
        transactionId: "escrow-1",
      },
    });
  });

  it("keeps local read flags when delayed sync returns stale unread remote state", () => {
    const local: Notification[] = [
      {
        id: "n1",
        title: "A",
        message: "a",
        type: "payment",
        read: true,
        createdAt: 2,
      },
      {
        id: "local-only",
        title: "B",
        message: "b",
        type: "system",
        read: false,
        createdAt: 1,
      },
    ];
    const remote: Notification[] = [
      {
        id: "n1",
        title: "A",
        message: "a",
        type: "payment",
        read: false,
        createdAt: 2,
      },
      {
        id: "n2",
        title: "C",
        message: "c",
        type: "payment",
        read: false,
        createdAt: 3,
      },
    ];

    const merged = mergeNotificationReadState(local, remote);

    expect(merged.find((item) => item.id === "n1")?.read).toBe(true);
    expect(merged.find((item) => item.id === "n2")?.read).toBe(false);
    expect(merged.find((item) => item.id === "local-only")).toBeTruthy();
    expect(merged[0].id).toBe("n2");
  });
});
