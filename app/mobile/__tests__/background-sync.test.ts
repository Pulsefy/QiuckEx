import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";
import { AppState } from "react-native";

import {
  DEFAULT_SYNC_SNAPSHOT,
  DEFAULT_BACKGROUND_SYNC_SETTINGS,
  SYNC_INTERVALS_MINUTES,
  getEffectiveSyncFrequency,
  getEffectiveSyncIntervalMs,
  getForegroundSyncIntervalMs,
  getSyncIntervalMsForFrequency,
  isLowBattery,
  isMeteredConnection,
  mergeSyncSnapshot,
  performBackgroundSync,
  triggerManualSync,
  type BackgroundSyncSettings,
  type SyncFrequency,
} from "../services/background-sync";

jest.mock("@react-native-community/netinfo", () => ({
  fetch: jest.fn(),
}));

jest.mock("../services/transactions", () => ({
  fetchTransactions: jest.fn(),
}));

jest.mock("../services/wallet-session", () => ({
  getWalletSession: jest.fn(),
}));

const mockedNetInfoFetch = NetInfo.fetch as jest.MockedFunction<
  typeof NetInfo.fetch
>;
const mockedGetBatteryLevelAsync = (jest.requireMock(
  "expo-battery",
) as any).getBatteryLevelAsync as jest.MockedFunction<any>;
const mockedFetchTransactions = (jest.requireMock(
  "../services/transactions",
) as any).fetchTransactions as jest.MockedFunction<any>;
const mockedGetWalletSession = (jest.requireMock(
  "../services/wallet-session",
) as any).getWalletSession as jest.MockedFunction<any>;

const ACCOUNT_ID =
  "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";

const BASE_NETWORK = {
  isConnected: true,
  isConnectionExpensive: false,
  type: "wifi",
  details: undefined,
};

const BASE_WALLET = {
  publicKey: ACCOUNT_ID,
};

beforeEach(() => {
  jest.clearAllMocks();
  mockedNetInfoFetch.mockResolvedValue({ ...BASE_NETWORK } as never);
  mockedGetBatteryLevelAsync.mockResolvedValue(0.8);
  mockedFetchTransactions.mockResolvedValue({
    items: [
      {
        amount: "10.0000000",
        asset: "XLM",
        memo: "Fresh",
        timestamp: "2026-04-23T12:00:00Z",
        txHash: "tx-new",
        pagingToken: "3",
        source: "GSOURCE",
        destination: ACCOUNT_ID,
        status: "Success",
      },
    ],
  } as never);
  mockedGetWalletSession.mockResolvedValue(BASE_WALLET as never);
  (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);
});

describe("getSyncIntervalMsForFrequency", () => {
  it("converts battery-saver to 60 minutes in ms", () => {
    expect(getSyncIntervalMsForFrequency("battery-saver")).toBe(60 * 60 * 1000);
  });

  it("converts balanced to 30 minutes in ms", () => {
    expect(getSyncIntervalMsForFrequency("balanced")).toBe(30 * 60 * 1000);
  });

  it("converts frequent to 15 minutes in ms", () => {
    expect(getSyncIntervalMsForFrequency("frequent")).toBe(15 * 60 * 1000);
  });
});

describe("getForegroundSyncIntervalMs", () => {
  it("uses the configured frequency by default", () => {
    expect(
      getForegroundSyncIntervalMs({ ...DEFAULT_BACKGROUND_SYNC_SETTINGS }),
    ).toBe(30 * 60 * 1000);
  });

  it("uses the effective frequency when provided", () => {
    expect(
      getForegroundSyncIntervalMs(
        { ...DEFAULT_BACKGROUND_SYNC_SETTINGS, frequency: "frequent" },
        "battery-saver",
      ),
    ).toBe(60 * 60 * 1000);
  });
});

describe("isMeteredConnection", () => {
  it("returns false for wifi", () => {
    expect(isMeteredConnection(BASE_NETWORK)).toBe(false);
  });

  it("returns true when isConnectionExpensive is set", () => {
    expect(
      isMeteredConnection({ ...BASE_NETWORK, isConnectionExpensive: true }),
    ).toBe(true);
  });

  it("returns true when details.isConnectionExpensive is set", () => {
    expect(
      isMeteredConnection({
        ...BASE_NETWORK,
        details: { isConnectionExpensive: true },
      }),
    ).toBe(true);
  });
});

describe("isLowBattery", () => {
  it("returns false when battery level is healthy", async () => {
    mockedGetBatteryLevelAsync.mockResolvedValue(0.5);
    expect(await isLowBattery()).toBe(false);
  });

  it("returns true when battery level is below 20%", async () => {
    mockedGetBatteryLevelAsync.mockResolvedValue(0.15);
    expect(await isLowBattery()).toBe(true);
  });
});

describe("getEffectiveSyncFrequency", () => {
  it("returns battery-saver when the user already selected it", async () => {
    const settings: BackgroundSyncSettings = {
      ...DEFAULT_BACKGROUND_SYNC_SETTINGS,
      frequency: "battery-saver",
    };
    expect(await getEffectiveSyncFrequency(settings)).toBe("battery-saver");
  });

  it("returns the selected frequency when battery is healthy and network is unmetered", async () => {
    const settings: BackgroundSyncSettings = {
      ...DEFAULT_BACKGROUND_SYNC_SETTINGS,
      frequency: "frequent",
    };
    expect(await getEffectiveSyncFrequency(settings)).toBe("frequent");
  });

  it("backs off to battery-saver on low battery", async () => {
    mockedGetBatteryLevelAsync.mockResolvedValue(0.1);
    const settings: BackgroundSyncSettings = {
      ...DEFAULT_BACKGROUND_SYNC_SETTINGS,
      frequency: "frequent",
    };
    expect(await getEffectiveSyncFrequency(settings)).toBe("battery-saver");
  });

  it("backs off to battery-saver on metered connections", async () => {
    mockedNetInfoFetch.mockResolvedValue({
      ...BASE_NETWORK,
      isConnectionExpensive: true,
    } as never);
    const settings: BackgroundSyncSettings = {
      ...DEFAULT_BACKGROUND_SYNC_SETTINGS,
      frequency: "balanced",
    };
    expect(await getEffectiveSyncFrequency(settings)).toBe("battery-saver");
  });
});

describe("getEffectiveSyncIntervalMs", () => {
  it("returns the interval matching the effective frequency", async () => {
    mockedNetInfoFetch.mockResolvedValue({
      ...BASE_NETWORK,
      isConnectionExpensive: true,
    } as never);
    const settings: BackgroundSyncSettings = {
      ...DEFAULT_BACKGROUND_SYNC_SETTINGS,
      frequency: "frequent",
    };
    expect(await getEffectiveSyncIntervalMs(settings)).toBe(
      SYNC_INTERVALS_MINUTES["battery-saver"] * 60 * 1000,
    );
  });
});

describe("performBackgroundSync", () => {
  it("skips sync when battery is low", async () => {
    mockedGetBatteryLevelAsync.mockResolvedValue(0.05);

    const result = await performBackgroundSync("foreground");

    expect(result.status).toBe("skipped");
    expect(result.detail).toBe("low-battery");
    expect(mockedFetchTransactions).not.toHaveBeenCalled();
  });

  it("skips sync on metered connections", async () => {
    mockedNetInfoFetch.mockResolvedValue({
      ...BASE_NETWORK,
      isConnectionExpensive: true,
    } as never);

    const result = await performBackgroundSync("foreground");

    expect(result.status).toBe("skipped");
    expect(result.detail).toBe("metered-connection");
    expect(mockedFetchTransactions).not.toHaveBeenCalled();
  });

  it("yields cleanly when the fetch is suspended mid-sync", async () => {
    jest.useFakeTimers();

    mockedFetchTransactions.mockImplementation(
      () =>
        new Promise(() => {
          /* never resolves */
        }),
    );

    const storedSnapshot = { ...DEFAULT_SYNC_SNAPSHOT, lastSyncedAt: Date.now() };
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify(storedSnapshot),
    );

    const promise = performBackgroundSync("background");

    await jest.advanceTimersByTimeAsync(31_000);
    await Promise.resolve();

    const result = await promise;

    expect(result.status).toBe("failed");
    expect(result.detail).toBe("sync-timeout");
    expect(result.snapshot.lastSyncedAt).toBe(storedSnapshot.lastSyncedAt);
    expect(mockedFetchTransactions).toHaveBeenCalledTimes(1);

    jest.useRealTimers();
  }, 40000);

  it("returns updated snapshot on success", async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify({ ...DEFAULT_SYNC_SNAPSHOT, lastSyncedAt: Date.now() }),
    );

    const result = await performBackgroundSync("manual");

    expect(result.status).toBe("updated");
    expect(result.reason).toBe("manual");
    expect(result.snapshot.notifications).toHaveLength(1);
  });

  it("does not corrupt snapshot when fetch throws", async () => {
    mockedFetchTransactions.mockRejectedValue(
      new Error("Network request failed."),
    );
    const savedSnapshot = { ...DEFAULT_SYNC_SNAPSHOT, lastSyncedAt: 12345 };
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify(savedSnapshot),
    );

    const result = await performBackgroundSync("foreground");

    expect(result.status).toBe("failed");
    expect(result.detail).toBe("fetch-failed");
    expect(result.snapshot.lastSyncedAt).toBe(savedSnapshot.lastSyncedAt);
  });
});

describe("triggerManualSync", () => {
  it("invokes performBackgroundSync with manual reason", async () => {
    mockedFetchTransactions.mockResolvedValue({
      items: [],
    } as never);

    const result = await triggerManualSync();

    expect(result.status).toBe("updated");
    expect(result.reason).toBe("manual");
    expect(mockedFetchTransactions).toHaveBeenCalledTimes(1);
  });
});

describe("SYNC_INTERVALS_MINUTES", () => {
  it("has conservative defaults for all frequencies", () => {
    expect(SYNC_INTERVALS_MINUTES["battery-saver"]).toBeGreaterThanOrEqual(60);
    expect(SYNC_INTERVALS_MINUTES.balanced).toBeGreaterThanOrEqual(30);
    expect(SYNC_INTERVALS_MINUTES.frequent).toBeGreaterThanOrEqual(15);
  });
});
