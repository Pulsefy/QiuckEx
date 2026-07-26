import React from "react";
import renderer, { act } from "react-test-renderer";
import QuickReceiveScreen from "../app/quick-receive";

const mockPush = jest.fn();

jest.mock("expo-router", () => ({
  useRouter: () => ({
    push: mockPush,
  }),
}));

jest.mock("expo-clipboard", () => ({
  setStringAsync: jest.fn(async () => true),
}));

jest.mock("react-native-qrcode-svg", () => "QRCode");

let mockWalletContext = {
  connected: false,
  publicKey: undefined as string | undefined,
  network: "testnet" as const,
  walletType: undefined as any,
};

jest.mock("../hooks/useWallet", () => ({
  useWallet: () => ({
    wallet: mockWalletContext,
  }),
}));

const mockLightTheme = {
  background: "#ffffff",
  surface: "#f5f5f5",
  textPrimary: "#111111",
  textSecondary: "#444444",
  qrBackground: "#ffffff",
  qrForeground: "#000000",
  chipBg: "#e5e7eb",
  chipText: "#1f2937",
  status: {
    info: "#3b82f6",
    success: "#22c55e",
    warning: "#f59e0b",
  },
  buttonPrimaryText: "#ffffff",
};

const mockDarkTheme = {
  background: "#111827",
  surface: "#1f2937",
  textPrimary: "#f9fafb",
  textSecondary: "#9ca3af",
  qrBackground: "#ffffff",
  qrForeground: "#000000",
  chipBg: "#374151",
  chipText: "#f3f4f6",
  status: {
    info: "#60a5fa",
    success: "#4ade80",
    warning: "#fbbf24",
  },
  buttonPrimaryText: "#111827",
};

let mockCurrentTheme = mockLightTheme;

jest.mock("../src/theme/ThemeContext", () => ({
  useTheme: () => ({
    theme: mockCurrentTheme,
  }),
}));

describe("<QuickReceiveScreen />", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockCurrentTheme = mockLightTheme;
    mockWalletContext = {
      connected: false,
      publicKey: undefined,
      network: "testnet",
      walletType: undefined,
    };
  });

  it("renders disconnected / guest fallback state correctly", () => {
    let tree: renderer.ReactTestRenderer;

    act(() => {
      tree = renderer.create(<QuickReceiveScreen />);
    });

    const json = tree!.toJSON();
    expect(json).toBeDefined();
    expect(JSON.stringify(json)).toContain("No wallet connected");
    expect(JSON.stringify(json)).toContain("Connect Wallet");
    expect(json).toMatchSnapshot("quick-receive-disconnected-fallback");
  });

  it("renders connected state with real account context and QR code", () => {
    mockWalletContext = {
      connected: true,
      publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
      network: "testnet",
      walletType: "freighter",
    };

    let tree: renderer.ReactTestRenderer;

    act(() => {
      tree = renderer.create(<QuickReceiveScreen />);
    });

    const json = tree!.toJSON();
    expect(json).toBeDefined();
    expect(JSON.stringify(json)).toContain("FREIGHTER");
    expect(JSON.stringify(json)).toContain("TESTNET");
    expect(JSON.stringify(json)).toContain("GAMOSF...QSLGLP");
    expect(JSON.stringify(json)).toContain("Copy Link");
    expect(JSON.stringify(json)).toContain("Copy Address");
    expect(JSON.stringify(json)).toContain("Share");
    expect(json).toMatchSnapshot("quick-receive-connected-real-account");
  });

  it("renders screenshot snapshots in dark mode for connected and disconnected states", () => {
    mockCurrentTheme = mockDarkTheme;

    // Disconnected state screenshot snapshot
    let treeDisconnected: renderer.ReactTestRenderer;
    act(() => {
      treeDisconnected = renderer.create(<QuickReceiveScreen />);
    });
    expect(treeDisconnected!.toJSON()).toMatchSnapshot("quick-receive-disconnected-dark");

    // Connected state screenshot snapshot
    mockWalletContext = {
      connected: true,
      publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
      network: "mainnet",
      walletType: "lobstr",
    };

    let treeConnected: renderer.ReactTestRenderer;
    act(() => {
      treeConnected = renderer.create(<QuickReceiveScreen />);
    });
    expect(treeConnected!.toJSON()).toMatchSnapshot("quick-receive-connected-dark");
  });
});
