import React from "react";
import renderer, { act } from "react-test-renderer";
import TestnetFundingHelper from "../components/wallet/TestnetFundingHelper";

// ── Mocks ────────────────────────────────────────────────────────────────────

let mockWalletState = {
  connected: false,
  network: "testnet",
  publicKey: undefined as string | undefined,
};

jest.mock("../hooks/useWalletContext", () => ({
  useWalletContext: () => ({
    wallet: mockWalletState,
  }),
}));

jest.mock("../src/theme/ThemeContext", () => ({
  useTheme: () => ({
    theme: {
      background: "#fff",
      surface: "#f5f5f5",
      border: "#ddd",
      borderLight: "#eee",
      textPrimary: "#111",
      textSecondary: "#444",
      textMuted: "#666",
      link: "#0a84ff",
      buttonPrimaryBg: "#111",
      buttonPrimaryText: "#fff",
      buttonSecondaryBg: "#fff",
      buttonSecondaryBorder: "#111",
      buttonSecondaryText: "#111",
      status: {
        success: "green",
        successBg: "#e6ffe6",
        warning: "orange",
        warningBg: "#fff5e6",
        error: "red",
        errorBg: "#ffe6e6",
        info: "blue",
        infoBg: "#e6f2ff",
      },
    },
  }),
}));

jest.mock("expo-web-browser", () => ({
  openBrowserAsync: jest.fn(async () => ({ type: "cancel" })),
  WebBrowserPresentationStyle: { AUTOMATIC: 0 },
}));

jest.mock("expo-linking", () => ({
  openURL: jest.fn(async () => true),
}));

// ── Tests ────────────────────────────────────────────────────────────────────

describe("<TestnetFundingHelper />", () => {
  let originalFetch: typeof global.fetch;

  beforeAll(() => {
    originalFetch = global.fetch;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockWalletState = {
      connected: false,
      network: "testnet",
      publicKey: undefined,
    };
    // Default mock of fetch to return a pending promise to avoid immediate resolution issues
    global.fetch = jest.fn(() => new Promise(() => {}));
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  it("returns null if the wallet is disconnected", () => {
    mockWalletState.connected = false;
    let tree: renderer.ReactTestRenderer;
    act(() => {
      tree = renderer.create(<TestnetFundingHelper />);
    });
    expect(tree!.toJSON()).toBeNull();
  });

  it("renders a warning badge and returns no balance check if wallet is on mainnet", () => {
    mockWalletState.connected = true;
    mockWalletState.network = "mainnet";
    mockWalletState.publicKey = "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";

    let tree: renderer.ReactTestRenderer;
    act(() => {
      tree = renderer.create(<TestnetFundingHelper />);
    });

    const json = tree!.toJSON();
    expect(json).not.toBeNull();
    // Should find the text notifying the user that it is testnet-only
    const textStr = JSON.stringify(json);
    expect(textStr).toContain("mainnet");
    expect(textStr).toContain("TESTNET ONLY");
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("performs balance check and displays unfunded state when Horizon returns 404", async () => {
    mockWalletState.connected = true;
    mockWalletState.network = "testnet";
    mockWalletState.publicKey = "G_TEST_PUBLIC_KEY";

    // Horizon returns 404 (Not Found) for unfunded accounts
    global.fetch = jest.fn().mockResolvedValue({
      status: 404,
      ok: false,
    });

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(<TestnetFundingHelper />);
    });

    const json = tree!.toJSON();
    const textStr = JSON.stringify(json);
    expect(textStr).toContain("Not Ready (Unfunded)");
    expect(textStr).toContain("0 XLM");
    expect(global.fetch).toHaveBeenCalledWith(
      "https://horizon-testnet.stellar.org/accounts/G_TEST_PUBLIC_KEY"
    );
  });

  it("displays low-balance state when Horizon returns 200 with balance < 5.0", async () => {
    mockWalletState.connected = true;
    mockWalletState.network = "testnet";
    mockWalletState.publicKey = "G_TEST_PUBLIC_KEY";

    global.fetch = jest.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        balances: [{ asset_type: "native", balance: "4.5000000" }],
      }),
    });

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(<TestnetFundingHelper />);
    });

    const json = tree!.toJSON();
    const textStr = JSON.stringify(json);
    expect(textStr).toContain("Not Ready (Low Balance)");
    expect(textStr).toContain("4.5 XLM");
  });

  it("displays ready state when Horizon returns 200 with balance >= 5.0", async () => {
    mockWalletState.connected = true;
    mockWalletState.network = "testnet";
    mockWalletState.publicKey = "G_TEST_PUBLIC_KEY";

    global.fetch = jest.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        balances: [{ asset_type: "native", balance: "150.7500000" }],
      }),
    });

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(<TestnetFundingHelper />);
    });

    const json = tree!.toJSON();
    const textStr = JSON.stringify(json);
    expect(textStr).toContain("Ready (Funded)");
    expect(textStr).toContain("150.75 XLM");
  });

  it("handles Horizon fetch error gracefully", async () => {
    mockWalletState.connected = true;
    mockWalletState.network = "testnet";
    mockWalletState.publicKey = "G_TEST_PUBLIC_KEY";

    global.fetch = jest.fn().mockRejectedValue(new Error("Network connection lost"));

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(<TestnetFundingHelper />);
    });

    const json = tree!.toJSON();
    const textStr = JSON.stringify(json);
    expect(textStr).toContain("Readiness Error");
    expect(textStr).toContain("Network connection lost");
  });

  it("funds the wallet using Friendbot and refreshes balance on success", async () => {
    mockWalletState.connected = true;
    mockWalletState.network = "testnet";
    mockWalletState.publicKey = "G_TEST_PUBLIC_KEY";

    // First call is initial balance check (returns 404).
    // Second call is Friendbot trigger (returns 200).
    // Third call is the automatic balance refetch after funding (returns 200 with 10000 XLM).
    let callCount = 0;
    global.fetch = jest.fn().mockImplementation(async (url) => {
      callCount++;
      if (url.includes("horizon-testnet.stellar.org")) {
        if (callCount === 1) {
          return { status: 404, ok: false };
        } else {
          return {
            status: 200,
            ok: true,
            json: async () => ({
              balances: [{ asset_type: "native", balance: "10000.0000000" }],
            }),
          };
        }
      } else if (url.includes("friendbot.stellar.org")) {
        return { status: 200, ok: true };
      }
      return { status: 500, ok: false };
    });

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(<TestnetFundingHelper />);
    });

    // Find the Friendbot button
    const inst = tree!.root;
    const findTextNode = inst.find(
      (node) => (node.type as any) === "Text" && node.props.children === "Fund via Faucet"
    );
    let parent = findTextNode.parent;
    while (parent && !parent.props.onPress) {
      parent = parent.parent;
    }
    const fundButton = parent;
    expect(fundButton).toBeDefined();

    // Click it
    await act(async () => {
      fundButton!.props.onPress();
    });

    // Verify Friendbot fetch was executed
    expect(global.fetch).toHaveBeenCalledWith(
      "https://friendbot.stellar.org/?addr=G_TEST_PUBLIC_KEY"
    );

    // Verify the status changes to success and balance gets updated to 10,000 XLM
    const textStr = JSON.stringify(tree!.toJSON());
    expect(textStr).toContain("Faucet successfully funded this account!");
    expect(textStr).toContain("10,000 XLM");
    expect(textStr).toContain("Ready (Funded)");
  });
});
