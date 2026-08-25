import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";
import {
  initializeCrashMonitoring,
  captureUnhandledError,
  captureNativeCrash,
  setCrashMonitoringFetch,
  resetCrashMonitoringState,
  CRASH_SUBMIT_ACTION,
} from "../services/crash-monitoring";
import { getOfflineQueue } from "../services/offline-queue";

jest.mock("@react-native-async-storage/async-storage", () => {
  let store: Record<string, string> = {};
  return {
    getItem: jest.fn(async (key) => store[key] ?? null),
    setItem: jest.fn(async (key, value) => {
      store[key] = value;
    }),
    removeItem: jest.fn(async (key) => {
      delete store[key];
    }),
    clear: jest.fn(async () => {
      store = {};
    }),
  };
});

jest.mock("@react-native-community/netinfo", () => {
  let isConnected = true;
  let listener: ((state: any) => void) | null = null;
  return {
    fetch: jest.fn(async () => ({
      isConnected,
      isInternetReachable: isConnected,
    })),
    addEventListener: jest.fn((cb) => {
      listener = cb;
      return () => {
        listener = null;
      };
    }),
    // Helper to simulate connection change in tests
    setConnected: (connected: boolean) => {
      isConnected = connected;
      if (listener) {
        listener({ isConnected: connected, isInternetReachable: connected });
      }
    },
  };
});

describe("Crash Monitoring Service", () => {
  let mockFetch: jest.Mock;

  beforeEach(async () => {
    jest.clearAllMocks();
    await AsyncStorage.clear();
    resetCrashMonitoringState();

    mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    setCrashMonitoringFetch(mockFetch as any);

    // Default to online
    (NetInfo as any).setConnected(true);
  });

  afterEach(() => {
    resetCrashMonitoringState();
  });

  it("should set global error handler upon initialization", () => {
    const originalHandler = global.ErrorUtils?.getGlobalHandler();
    initializeCrashMonitoring();

    expect(global.ErrorUtils?.getGlobalHandler()).not.toBe(originalHandler);
  });

  it("should capture unhandled JS errors and submit payload", async () => {
    const error = new Error("JS Crash");
    error.stack = "Error: JS Crash\n  at App.tsx:10:20";

    await captureUnhandledError(error, "Unhandled JavaScript Error");

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, requestOptions] = mockFetch.mock.calls[0];
    expect(url).toContain("/crash-reporting/submit");
    expect(requestOptions.method).toBe("POST");

    const body = JSON.parse(requestOptions.body);
    expect(body.userMessage).toBe("Unhandled JavaScript Error: JS Crash");
    expect(body.errorDetails).toContain("Error: JS Crash");
    expect(body.errorDetails).toContain("at App.tsx:10:20");

    const env = JSON.parse(body.environment);
    expect(env.appVersion).toBeDefined();
    expect(env.buildMetadata).toBeDefined();
    expect(env.platform).toBeDefined();
    expect(env.osVersion).toBeDefined();
  });

  it("should capture native crashes explicitly", async () => {
    const error = new Error("Native segfault");
    error.stack = "NativeStackFrame1\nNativeStackFrame2";

    await captureNativeCrash(error);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.userMessage).toBe("Native Crash: Native segfault");
    expect(body.errorDetails).toContain("NativeStackFrame1");
  });

  it("should scrub sensitive wallet seeds and PII before submission", async () => {
    const secretKey = "SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX";
    const publicKey = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX";
    const email = "user@example.com";
    const phone = "555-555-5555";
    const creditCard = "4111 1111 1111 1111";

    const error = new Error(
      `Crash: seed ${secretKey}, wallet ${publicKey}, email ${email}, phone ${phone}, card ${creditCard}`
    );

    await captureUnhandledError(error, "Unhandled JavaScript Error");

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);

    // Verify scrubbing
    expect(body.userMessage).not.toContain(secretKey);
    expect(body.userMessage).not.toContain(email);
    expect(body.userMessage).not.toContain(phone);
    expect(body.userMessage).not.toContain(creditCard);

    expect(body.userMessage).toContain("[REDACTED_SECRET_KEY]");
    expect(body.userMessage).toContain("[EMAIL]");
    expect(body.userMessage).toContain("[PHONE]");
    expect(body.userMessage).toContain("[CARD]");
    expect(body.userMessage).toContain("GABC…UVWX");
  });

  it("should queue crash reports when offline", async () => {
    (NetInfo as any).setConnected(false);

    const error = new Error("Offline crash");
    await captureUnhandledError(error, "Unhandled JavaScript Error");

    // Fetch should not be called since offline
    expect(mockFetch).not.toHaveBeenCalled();

    // Verify item is queued in offline queue
    const queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].type).toBe(CRASH_SUBMIT_ACTION);
    expect(queue[0].payload.userMessage).toBe("Unhandled JavaScript Error: Offline crash");
  });

  it("should submit queued reports on reconnect", async () => {
    initializeCrashMonitoring();

    // 1. Trigger error while offline
    (NetInfo as any).setConnected(false);
    const error = new Error("Offline crash to reconnect");
    await captureUnhandledError(error, "Unhandled JavaScript Error");

    let queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(mockFetch).not.toHaveBeenCalled();

    // 2. Simulate transition to online status (reconnect)
    (NetInfo as any).setConnected(true);

    // Allow async microtasks/promises to process
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Verify it was sent and removed/marked completed in queue
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.userMessage).toBe("Unhandled JavaScript Error: Offline crash to reconnect");
  });
});
