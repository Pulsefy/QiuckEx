import NetInfo from "@react-native-community/netinfo";
import {
  enqueueAction,
  getOfflineQueue,
  processOfflineQueue,
} from "../services/offline-queue";
import {
  MARK_ALL_READ_ACTION,
  MARK_READ_ACTION,
  flushNotificationReadQueue,
  registerNotificationReadHandlers,
  syncMarkAllNotificationsRead,
  syncMarkNotificationRead,
} from "../services/notification-read-sync";
import {
  markAllInAppNotificationsRead,
  markInAppNotificationRead,
} from "../services/in-app-notifications";

jest.mock("@react-native-async-storage/async-storage", () => {
  let store: Record<string, string> = {};
  return {
    getItem: jest.fn(async (key: string) => store[key] ?? null),
    setItem: jest.fn(async (key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: jest.fn(async (key: string) => {
      delete store[key];
    }),
    clear: jest.fn(async () => {
      store = {};
    }),
  };
});

jest.mock("@react-native-community/netinfo", () => ({
  fetch: jest.fn(),
}));

jest.mock("../services/in-app-notifications", () => ({
  markInAppNotificationRead: jest.fn(async () => undefined),
  markAllInAppNotificationsRead: jest.fn(async () => undefined),
}));

describe("notification read state sync", () => {
  beforeEach(async () => {
    jest.clearAllMocks();
    const AsyncStorage = require("@react-native-async-storage/async-storage");
    await AsyncStorage.clear();
    registerNotificationReadHandlers();
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: true,
      isInternetReachable: true,
    });
  });

  it("syncs a single mark-read mutation when online", async () => {
    const result = await syncMarkNotificationRead("notif-1");

    expect(result).toEqual({ status: "synced" });
    expect(markInAppNotificationRead).toHaveBeenCalledWith("notif-1");
    expect(await getOfflineQueue()).toHaveLength(0);
  });

  it("queues a single mark-read mutation when offline", async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: false,
      isInternetReachable: false,
    });

    const result = await syncMarkNotificationRead("notif-offline");

    expect(result).toEqual({ status: "queued", reason: "offline" });
    expect(markInAppNotificationRead).not.toHaveBeenCalled();

    const queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].type).toBe(MARK_READ_ACTION);
    expect(queue[0].payload).toEqual({ id: "notif-offline" });
  });

  it("queues a single mark-read mutation when the request fails", async () => {
    (markInAppNotificationRead as jest.Mock).mockRejectedValueOnce(
      new Error("Server error (500)"),
    );

    const result = await syncMarkNotificationRead("notif-fail");

    expect(result).toEqual({ status: "queued", reason: "request-failed" });
    const queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].payload).toEqual({ id: "notif-fail" });
  });

  it("syncs a batch mark-all-read mutation when online", async () => {
    const result = await syncMarkAllNotificationsRead("GPUBLICKEY");

    expect(result).toEqual({ status: "synced" });
    expect(markAllInAppNotificationsRead).toHaveBeenCalledWith("GPUBLICKEY");
    expect(await getOfflineQueue()).toHaveLength(0);
  });

  it("queues a batch mark-all-read mutation when offline", async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: false,
      isInternetReachable: false,
    });

    const result = await syncMarkAllNotificationsRead("GPUBLICKEY");

    expect(result).toEqual({ status: "queued", reason: "offline" });
    expect(markAllInAppNotificationsRead).not.toHaveBeenCalled();

    const queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].type).toBe(MARK_ALL_READ_ACTION);
    expect(queue[0].payload).toEqual({ publicKey: "GPUBLICKEY" });
  });

  it("flushes queued single and batch read actions after reconnect", async () => {
    await enqueueAction(MARK_READ_ACTION, { id: "queued-1" });
    await enqueueAction(MARK_ALL_READ_ACTION, { publicKey: "GPUBLICKEY" });

    await flushNotificationReadQueue();

    expect(markInAppNotificationRead).toHaveBeenCalledWith("queued-1");
    expect(markAllInAppNotificationsRead).toHaveBeenCalledWith("GPUBLICKEY");

    const queue = await getOfflineQueue();
    expect(queue.every((item) => item.status === "completed")).toBe(true);
  });

  it("does not corrupt local intent when delayed sync eventually succeeds", async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: false,
      isInternetReachable: false,
    });

    await syncMarkNotificationRead("delayed-1");
    await syncMarkAllNotificationsRead("GPUBLICKEY");

    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: true,
      isInternetReachable: true,
    });

    await processOfflineQueue();

    expect(markInAppNotificationRead).toHaveBeenCalledWith("delayed-1");
    expect(markAllInAppNotificationsRead).toHaveBeenCalledWith("GPUBLICKEY");
  });

  it("skips sync when required identifiers are missing", async () => {
    await expect(syncMarkNotificationRead("")).resolves.toEqual({
      status: "skipped",
      reason: "missing-id",
    });
    await expect(syncMarkAllNotificationsRead(null)).resolves.toEqual({
      status: "skipped",
      reason: "missing-public-key",
    });
  });
});
