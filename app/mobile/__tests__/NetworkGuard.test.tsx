import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react-native";
import React from "react";
import { useNetworkGuard } from "../hooks/useNetworkGuard";
import { NetworkGuardProvider, useNetworkGuardContext } from "../contexts/NetworkGuardContext";
import { GlobalNetworkBanner } from "../components/wallet/GlobalNetworkBanner";
import {
  NetworkMismatchGuard,
  NetworkMismatchGuardButton,
} from "../components/wallet/NetworkMismatchGuard";
import { WalletSwitchHelpModal } from "../components/wallet/WalletSwitchHelpModal";
import { WalletProvider } from "../hooks/useWalletContext";

// Mock wallet context
vi.mock("../hooks/useWalletContext", () => {
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
    connect: vi.fn(),
    disconnect: vi.fn(),
    switchAccount: vi.fn(),
    switchNetwork: vi.fn(),
    clearError: vi.fn(),
  });

  return {
    WalletProvider: ({ children }: any) =>
      React.createElement(WalletContext.Provider, { value: mockWalletState }, children),
    useWalletContext: vi.fn(() => ({
      wallet: mockWalletState,
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    })),
  };
});

/**
 * TEST SUITE: Network Guard Mismatch Detection
 */
describe("useNetworkGuard - Mismatch Detection", () => {
  it("should detect network mismatch when wallet is on PUBLIC and app expects TESTNET", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "mainnet",
        walletType: "freighter",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      const guard = useNetworkGuard("testnet");
      return (
        <>
          <div data-testid="mismatch">{guard.isMismatched ? "YES" : "NO"}</div>
          <div data-testid="current-net">{guard.currentNetwork}</div>
          <div data-testid="expected-net">{guard.expectedNetwork}</div>
        </>
      );
    }

    const { getByTestId } = render(<TestComponent />);

    expect(getByTestId("mismatch").textContent).toBe("YES");
    expect(getByTestId("current-net").textContent).toBe("mainnet");
    expect(getByTestId("expected-net").textContent).toBe("testnet");
  });

  it("should NOT detect mismatch when wallet is on TESTNET and app expects TESTNET", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "testnet",
        walletType: "freighter",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      const guard = useNetworkGuard("testnet");
      return (
        <div data-testid="mismatch">{guard.isMismatched ? "YES" : "NO"}</div>
      );
    }

    const { getByTestId } = render(<TestComponent />);

    expect(getByTestId("mismatch").textContent).toBe("NO");
  });

  it("should track isConnected status", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: false,
        publicKey: undefined,
        network: "testnet",
        walletType: undefined,
        connectedAt: undefined,
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      const guard = useNetworkGuard("testnet");
      return (
        <div data-testid="connected">
          {guard.isConnected ? "CONNECTED" : "DISCONNECTED"}
        </div>
      );
    }

    const { getByTestId } = render(<TestComponent />);

    expect(getByTestId("connected").textContent).toBe("DISCONNECTED");
  });

  it("should identify wallet type correctly", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "testnet",
        walletType: "xbull",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      const guard = useNetworkGuard("testnet");
      return <div data-testid="wallet">{guard.walletType}</div>;
    }

    const { getByTestId } = render(<TestComponent />);

    expect(getByTestId("wallet").textContent).toBe("xbull");
  });
});

/**
 * TEST SUITE: Network Guard Context
 */
describe("NetworkGuardContext", () => {
  it("should provide guard state through context", () => {
    function TestComponent() {
      const { guard, config } = useNetworkGuardContext();
      return (
        <>
          <div data-testid="is-mismatch">
            {guard.isMismatched ? "BLOCKED" : "OK"}
          </div>
          <div data-testid="config-network">{config.expectedNetwork}</div>
        </>
      );
    }

    const { getByTestId } = render(
      <NetworkGuardProvider expectedNetwork="testnet">
        <TestComponent />
      </NetworkGuardProvider>,
    );

    expect(getByTestId("config-network").textContent).toBe("testnet");
  });

  it("should throw error when used outside provider", () => {
    function TestComponent() {
      useNetworkGuardContext();
      return <div>Test</div>;
    }

    expect(() => render(<TestComponent />)).toThrow(
      "useNetworkGuardContext must be called within a NetworkGuardProvider",
    );
  });
});

/**
 * TEST SUITE: Global Network Banner
 */
describe("GlobalNetworkBanner", () => {
  it("should render nothing when wallet is not connected", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: false,
        publicKey: undefined,
        network: "testnet",
        walletType: undefined,
        connectedAt: undefined,
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      return (
        <NetworkGuardProvider>
          <GlobalNetworkBanner />
        </NetworkGuardProvider>
      );
    }

    const { container } = render(<TestComponent />);
    expect(container.textContent).toBe("");
  });

  it("should render normal banner when connected and no mismatch", () => {
    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <GlobalNetworkBanner />
        </NetworkGuardProvider>
      );
    }

    const { getByText, queryByText } = render(<TestComponent />);

    expect(getByText(/Stellar Testnet Mode/i)).toBeTruthy();
    expect(queryByText(/NETWORK MISMATCH/i)).toBeFalsy();
  });

  it("should render critical banner when network mismatch detected", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "mainnet",
        walletType: "freighter",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <GlobalNetworkBanner />
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);

    expect(getByText(/NETWORK MISMATCH/i)).toBeTruthy();
    expect(getByText(/Actions locked/i)).toBeTruthy();
  });
});

/**
 * TEST SUITE: Network Mismatch Guard Component
 */
describe("NetworkMismatchGuard", () => {
  it("should render children normally when no mismatch", () => {
    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <NetworkMismatchGuard>
            <div data-testid="protected-button">Pay Now</div>
          </NetworkMismatchGuard>
        </NetworkGuardProvider>
      );
    }

    const { getByTestId } = render(<TestComponent />);

    expect(getByTestId("protected-button").textContent).toBe("Pay Now");
  });

  it("should block and show warning when mismatch detected", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "mainnet",
        walletType: "freighter",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <NetworkMismatchGuard>
            <div data-testid="protected-button">Pay Now</div>
          </NetworkMismatchGuard>
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);

    expect(getByText(/Action Blocked/i)).toBeTruthy();
    expect(getByText(/Network Mismatch Detected/i)).toBeTruthy();
  });

  it("should call onBlocked callback when blocked action is tapped", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");
    const mockOnBlocked = vi.fn();

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "mainnet",
        walletType: "freighter",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <NetworkMismatchGuard onBlocked={mockOnBlocked}>
            <div>Pay Now</div>
          </NetworkMismatchGuard>
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);
    const blockedArea = getByText(/Action Blocked/i);

    fireEvent.press(blockedArea);

    expect(mockOnBlocked).toHaveBeenCalled();
  });

  it("should render button variant with correct blocked state", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "mainnet",
        walletType: "xbull",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <NetworkMismatchGuardButton>Refund Now</NetworkMismatchGuardButton>
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);

    expect(getByText(/Action Blocked/i)).toBeTruthy();
  });
});

/**
 * TEST SUITE: Wallet Switch Help Modal
 */
describe("WalletSwitchHelpModal", () => {
  it("should render with correct wallet instructions for Freighter", () => {
    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <WalletSwitchHelpModal visible={true} onClose={vi.fn()} />
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);

    expect(getByText(/Freighter Wallet/i)).toBeTruthy();
    expect(getByText(/Open the Freighter browser extension/i)).toBeTruthy();
  });

  it("should render with correct wallet instructions for xBull", () => {
    const { useWalletContext } = require("../hooks/useWalletContext");

    useWalletContext.mockReturnValue({
      wallet: {
        connected: true,
        publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
        network: "testnet",
        walletType: "xbull",
        connectedAt: Date.now(),
        error: undefined,
        isRestoring: false,
      },
      connect: vi.fn(),
      disconnect: vi.fn(),
      switchAccount: vi.fn(),
      switchNetwork: vi.fn(),
      clearError: vi.fn(),
    });

    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <WalletSwitchHelpModal visible={true} onClose={vi.fn()} />
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);

    expect(getByText(/xBull Wallet/i)).toBeTruthy();
  });

  it("should call onClose when close button is pressed", () => {
    const mockOnClose = vi.fn();

    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <WalletSwitchHelpModal visible={true} onClose={mockOnClose} />
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);
    const closeButton = getByText("✕");

    fireEvent.press(closeButton);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it("should not render when visible is false", () => {
    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <WalletSwitchHelpModal visible={false} onClose={vi.fn()} />
        </NetworkGuardProvider>
      );
    }

    const { queryByText } = render(<TestComponent />);

    expect(queryByText(/Network Setup Help/i)).toBeFalsy();
  });

  it("should display testnet requirement", () => {
    function TestComponent() {
      return (
        <NetworkGuardProvider expectedNetwork="testnet">
          <WalletSwitchHelpModal visible={true} onClose={vi.fn()} />
        </NetworkGuardProvider>
      );
    }

    const { getByText } = render(<TestComponent />);

    expect(getByText(/App requires: TESTNET/i)).toBeTruthy();
  });
});
