import React from "react";
import renderer, { act } from "react-test-renderer";
import { Text, View } from "react-native";
import { useNetworkGuard } from "../hooks/useNetworkGuard";
import { NetworkGuardProvider, useNetworkGuardContext } from "../contexts/NetworkGuardContext";
import { GlobalNetworkBanner } from "../components/wallet/GlobalNetworkBanner";
import {
  NetworkMismatchGuard,
  NetworkMismatchGuardButton,
} from "../components/wallet/NetworkMismatchGuard";
import { WalletSwitchHelpModal } from "../components/wallet/WalletSwitchHelpModal";

// Mock the build config so tests don't depend on expo-constants
jest.mock("../src/config/build", () => ({
  STELLAR_NETWORK: "testnet",
  APP_ENVIRONMENT: "development",
}));

// Polyfill global window/document for React Native test environments
// where window may exist but lack addEventListener (e.g. jest-expo preset).
beforeAll(() => {
  if (typeof globalThis !== "undefined") {
    if (typeof (globalThis as any).window === "undefined") {
      (globalThis as any).window = {};
    }
    if (typeof (globalThis as any).document === "undefined") {
      (globalThis as any).document = {
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        visibilityState: "visible" as const,
      };
    }
    if (typeof (globalThis as any).window.addEventListener !== "function") {
      (globalThis as any).window.addEventListener = jest.fn();
      (globalThis as any).window.removeEventListener = jest.fn();
    }
    if (typeof (globalThis as any).window.document === "undefined") {
      (globalThis as any).window.document = (globalThis as any).document;
    }
  }
});

// Mock wallet context
jest.mock("../hooks/useWalletContext", () => {
  const React = require("react");

  const mockWalletState = {
    connected: true,
    publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
    network: "testnet" as const,
    walletType: "freighter" as const,
    connectedAt: Date.now(),
    error: undefined,
    isRestoring: false,
  };

  const WalletContext = React.createContext({
    wallet: mockWalletState,
    connect: jest.fn(),
    disconnect: jest.fn(),
    switchAccount: jest.fn(),
    switchNetwork: jest.fn(),
    clearError: jest.fn(),
  });

  return {
    WalletProvider: ({ children }: any) =>
      React.createElement(WalletContext.Provider, { value: mockWalletState }, children),
    useWalletContext: jest.fn(() => ({
      wallet: mockWalletState,
      connect: jest.fn(),
      disconnect: jest.fn(),
      switchAccount: jest.fn(),
      switchNetwork: jest.fn(),
      clearError: jest.fn(),
    })),
  };
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function setWalletState(overrides: Record<string, any>) {
  const { useWalletContext } = require("../hooks/useWalletContext");
  const defaults = {
    connected: true,
    publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
    network: "testnet" as const,
    walletType: "freighter" as const,
    connectedAt: Date.now(),
    error: undefined,
    isRestoring: false,
  };
  useWalletContext.mockReturnValue({
    wallet: { ...defaults, ...overrides },
    connect: jest.fn(),
    disconnect: jest.fn(),
    switchAccount: jest.fn(),
    switchNetwork: jest.fn(),
    clearError: jest.fn(),
  });
}

function renderInProvider(element: React.ReactElement) {
  return renderer.create(
    <NetworkGuardProvider expectedNetwork="testnet">{element}</NetworkGuardProvider>,
  );
}

/**
 * TEST SUITE: Network Guard Mismatch Detection
 */
describe("useNetworkGuard - Mismatch Detection", () => {
  it("should detect network mismatch when wallet is on PUBLIC and app expects TESTNET", async () => {
    setWalletState({ network: "mainnet" });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    renderInProvider(<TestComponent />);
    await act(async () => {});

    expect(guardResult!.isMismatched).toBe(true);
    expect(guardResult!.currentNetwork).toBe("mainnet");
    expect(guardResult!.expectedNetwork).toBe("testnet");
  });

  it("should NOT detect mismatch when wallet is on TESTNET and app expects TESTNET", async () => {
    setWalletState({ network: "testnet" });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    renderInProvider(<TestComponent />);
    await act(async () => {});

    expect(guardResult!.isMismatched).toBe(false);
  });

  it("should track isConnected status", async () => {
    setWalletState({ connected: false });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    renderInProvider(<TestComponent />);
    await act(async () => {});

    expect(guardResult!.isConnected).toBe(false);
  });

  it("should identify wallet type correctly", async () => {
    setWalletState({ walletType: "xbull" });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    renderInProvider(<TestComponent />);
    await act(async () => {});

    expect(guardResult!.walletType).toBe("xbull");
  });
});

/**
 * TEST SUITE: Network Guard Context
 */
describe("NetworkGuardContext", () => {
  it("should provide guard state through context", async () => {
    let contextValue: any = null;

    function TestComponent() {
      contextValue = useNetworkGuardContext();
      return null;
    }

    renderInProvider(<TestComponent />);
    await act(async () => {});

    expect(contextValue.config.expectedNetwork).toBe("testnet");
    expect(contextValue.guard.isMismatched).toBe(false);
  });

  it("should throw error when used outside provider", () => {
    // useNetworkGuardContext reads from context which is undefined → throws.
    expect(() => {
      function TestComponent() {
        useNetworkGuardContext();
        return null;
      }

      renderer.act(() => {
        renderer.create(<TestComponent />);
      });
    }).toThrow();
  });
});

/**
 * TEST SUITE: Global Network Banner
 */
describe("GlobalNetworkBanner", () => {
  it("should show testnet idle banner when wallet is not connected and app is testnet", async () => {
    setWalletState({ connected: false });

    const tree = renderInProvider(<GlobalNetworkBanner />);
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const bannerText = texts.map((t) => t.props.children).flat().join(" ");

    expect(bannerText).toContain("Stellar Testnet Mode");
    tree.unmount();
  });

  it("should render normal banner when connected and no mismatch", async () => {
    setWalletState({ connected: true, network: "testnet" });

    const tree = renderInProvider(<GlobalNetworkBanner />);
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const bannerText = texts.map((t) => t.props.children).flat().join(" ");

    expect(bannerText).toContain("Stellar Testnet Mode");
    expect(bannerText).not.toContain("NETWORK MISMATCH");
    tree.unmount();
  });

  it("should render critical banner when network mismatch detected", async () => {
    setWalletState({ connected: true, network: "mainnet" });

    const tree = renderInProvider(<GlobalNetworkBanner />);
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const bannerText = texts.map((t) => t.props.children).flat().join(" ");

    expect(bannerText).toContain("NETWORK MISMATCH");
    expect(bannerText).toMatch(/mainnet/i);
    expect(bannerText).toMatch(/testnet/i);
    tree.unmount();
  });
});

/**
 * TEST SUITE: Network Mismatch Guard Component
 */
describe("NetworkMismatchGuard", () => {
  it("should render children normally when no mismatch", async () => {
    setWalletState({ connected: true, network: "testnet" });

    const tree = renderInProvider(
      <NetworkMismatchGuard>
        <View testID="protected-button">
          <Text>Pay Now</Text>
        </View>
      </NetworkMismatchGuard>,
    );
    await act(async () => {});

    const button = tree.root.findByProps({ testID: "protected-button" });
    expect(button).toBeDefined();
    expect(button.findByType(Text).props.children).toBe("Pay Now");
    tree.unmount();
  });

  it("should block and show warning when mismatch detected", async () => {
    setWalletState({ connected: true, network: "mainnet" });

    const tree = renderInProvider(
      <NetworkMismatchGuard>
        <View>
          <Text>Pay Now</Text>
        </View>
      </NetworkMismatchGuard>,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => t.props.children).flat().join(" ");

    expect(allText).toContain("Action Blocked");
    expect(allText).toContain("Tap for help");
    tree.unmount();
  });

  it("should call onBlocked callback when blocked action is tapped", async () => {
    setWalletState({ connected: true, network: "mainnet" });
    const mockOnBlocked = jest.fn();

    const tree = renderInProvider(
      <NetworkMismatchGuard onBlocked={mockOnBlocked}>
        <View>
          <Text>Pay Now</Text>
        </View>
      </NetworkMismatchGuard>,
    );
    await act(async () => {});

    const blockedText = tree.root.findAllByType(Text).find(
      (t) => String(t.props.children) === "Action Blocked",
    );
    expect(blockedText).toBeDefined();

    // Each TouchableOpacity in RN accepts onPress prop
    const touchables = tree.root.findAll(
      (node) => node.props && typeof node.props.onPress === "function",
    );
    act(() => {
      touchables.forEach((t) => t.props.onPress());
    });

    expect(mockOnBlocked).toHaveBeenCalled();
    tree.unmount();
  });

  it("should render button variant with correct blocked state", async () => {
    setWalletState({ connected: true, network: "mainnet", walletType: "xbull" });

    const tree = renderInProvider(
      <NetworkMismatchGuardButton>Refund Now</NetworkMismatchGuardButton>,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const buttonText = texts.map((t) => String(t.props.children)).join(" ");

    expect(buttonText).toContain("Action Blocked");
    tree.unmount();
  });
});

/**
 * TEST SUITE: Wallet Switch Help Modal
 */
describe("WalletSwitchHelpModal", () => {
  it("should render with correct wallet instructions for Freighter", async () => {
    setWalletState({ walletType: "freighter" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={true} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).toMatch(/freighter/i);
    expect(allText).toMatch(/Open Freighter/i);
    tree.unmount();
  });

  it("should render with correct wallet instructions for xBull", async () => {
    setWalletState({ walletType: "xbull", network: "testnet" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={true} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).toMatch(/xBull/i);
    tree.unmount();
  });

  it("should render instructions for LOBSTR wallet", async () => {
    setWalletState({ walletType: "lobstr", network: "mainnet" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={true} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).toMatch(/lobstr/i);
    expect(allText).toMatch(/Settings.*Advanced/i);
    tree.unmount();
  });

  it("should render instructions for Albedo wallet", async () => {
    setWalletState({ walletType: "albedo", network: "mainnet" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={true} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).toMatch(/Albedo/i);
    expect(allText).toMatch(/Switch.*Network.*Testnet/i);
    tree.unmount();
  });

  it("should show generic instructions for unknown wallet type", async () => {
    setWalletState({ walletType: undefined, network: "mainnet" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={true} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).toMatch(/your wallet/i);
    expect(allText).toMatch(/Open your Stellar wallet/i);
    tree.unmount();
  });

  it("should not render when visible is false", async () => {
    setWalletState({ walletType: "freighter" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={false} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    expect(() => root.findAllByType(Text)).not.toThrow();
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).not.toMatch(/Network Switch Guide/i);
    tree.unmount();
  });

  it("should display mismatch details with current and expected networks", async () => {
    setWalletState({ walletType: "freighter" });

    const tree = renderInProvider(
      <WalletSwitchHelpModal visible={true} onClose={jest.fn()} />,
    );
    await act(async () => {});

    const root = tree.root;
    const texts = root.findAllByType(Text);
    const allText = texts.map((t) => String(t.props.children)).join(" ");

    expect(allText).toMatch(/Mismatch Detected/i);
    expect(allText).toMatch(/TESTNET/i);
    tree.unmount();
  });
});

/**
 * TEST SUITE: Recovery Flow — Mismatch Resolution
 */
describe("Recovery Flow — Mismatch Resolution", () => {
  it("should clear mismatch when user switches wallet to correct network", async () => {
    setWalletState({ network: "mainnet" });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    const tree = renderInProvider(<TestComponent />);
    await act(async () => {});

    // Verify mismatch is detected
    expect(guardResult!.isMismatched).toBe(true);
    expect(guardResult!.currentNetwork).toBe("mainnet");

    // Simulate user switching wallet to testnet
    setWalletState({ network: "testnet" });

    // Trigger re-render
    await act(async () => {
      tree.update(
        <NetworkGuardProvider expectedNetwork="testnet">
          <TestComponent />
        </NetworkGuardProvider>,
      );
    });

    // Verify mismatch is cleared
    expect(guardResult!.isMismatched).toBe(false);
    expect(guardResult!.currentNetwork).toBe("testnet");

    tree.unmount();
  });

  it("should unblock actions when mismatch is resolved", async () => {
    setWalletState({ network: "mainnet" });

    const tree = renderInProvider(
      <NetworkMismatchGuard>
        <View testID="action">
          <Text>Send Payment</Text>
        </View>
      </NetworkMismatchGuard>,
    );
    await act(async () => {});

    // Guard blocks the action
    const texts1 = tree.root.findAllByType(Text);
    const allText1 = texts1.map((t) => String(t.props.children)).join(" ");
    expect(allText1).toContain("Action Blocked");

    // After switching to testnet, the guard should unblock
    setWalletState({ network: "testnet" });

    await act(async () => {
      tree.update(
        <NetworkGuardProvider expectedNetwork="testnet">
          <NetworkMismatchGuard>
            <View testID="action">
              <Text>Send Payment</Text>
            </View>
          </NetworkMismatchGuard>
        </NetworkGuardProvider>,
      );
    });

    // Action should now be accessible
    const texts2 = tree.root.findAllByType(Text);
    const allText2 = texts2.map((t) => String(t.props.children)).join(" ");
    expect(allText2).not.toContain("Action Blocked");
    expect(allText2).toContain("Send Payment");

    tree.unmount();
  });

  it("should restore blocked status if user switches back to wrong network", async () => {
    setWalletState({ network: "testnet" });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    const tree = renderInProvider(<TestComponent />);
    await act(async () => {});

    // Initially OK
    expect(guardResult!.isMismatched).toBe(false);

    // User switches to wrong network
    setWalletState({ network: "mainnet" });

    await act(async () => {
      tree.update(
        <NetworkGuardProvider expectedNetwork="testnet">
          <TestComponent />
        </NetworkGuardProvider>,
      );
    });

    // Mismatch is detected again
    expect(guardResult!.isMismatched).toBe(true);

    tree.unmount();
  });

  it("should not block when not connected regardless of network", async () => {
    setWalletState({ connected: false });

    const tree = renderInProvider(
      <NetworkMismatchGuard>
        <View testID="action">
          <Text>Send Payment</Text>
        </View>
      </NetworkMismatchGuard>,
    );
    await act(async () => {});

    const action = tree.root.findByProps({ testID: "action" });
    expect(action).toBeDefined();

    const allText = tree.root.findAllByType(Text).map((t) => String(t.props.children)).join(" ");
    expect(allText).not.toContain("Action Blocked");

    tree.unmount();
  });

  it("should detect mismatch for all supported wallet types", async () => {
    const walletTypes = ["freighter", "lobstr", "xbull", "albedo", "demo"] as const;

    for (const wType of walletTypes) {
      setWalletState({ walletType: wType, network: "mainnet" });

      let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

      function TestComponent() {
        guardResult = useNetworkGuard("testnet");
        return null;
      }

      const tree = renderInProvider(<TestComponent />);
      await act(async () => {});

      expect(guardResult!.isMismatched).toBe(true);
      expect(guardResult!.walletType).toBe(wType);

      tree.unmount();
    }
  });

  it("should recover by switching network in app state (switchNetwork)", async () => {
    setWalletState({ network: "mainnet", walletType: "freighter" });

    let guardResult: ReturnType<typeof useNetworkGuard> | null = null;

    function TestComponent() {
      guardResult = useNetworkGuard("testnet");
      return null;
    }

    const tree = renderInProvider(<TestComponent />);
    await act(async () => {});

    // Mismatch active
    expect(guardResult!.isMismatched).toBe(true);

    // Simulate switchNetwork from wallet context changing the network
    setWalletState({ network: "testnet", walletType: "freighter" });

    await act(async () => {
      tree.update(
        <NetworkGuardProvider expectedNetwork="testnet">
          <TestComponent />
        </NetworkGuardProvider>,
      );
    });

    // Mismatch cleared
    expect(guardResult!.isMismatched).toBe(false);
    expect(guardResult!.currentNetwork).toBe("testnet");

    tree.unmount();
  });
});
