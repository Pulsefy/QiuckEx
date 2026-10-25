import React from "react";
import renderer from "react-test-renderer";
import EscrowDetailScreen from "../app/escrow/[id]";
import { useEscrowDetail } from "../hooks/useEscrowDetail";
import type { EscrowDetail } from "../services/escrow";
import "../src/lib/i18n";
jest.mock("expo-router", () => ({
  useLocalSearchParams: () => ({ id: "escrow-123", status: "open" }),
  useRouter: () => ({ back: jest.fn() }),
}));

jest.mock("../hooks/useEscrowDetail", () => ({
  useEscrowDetail: jest.fn(),
}));

jest.mock("../hooks/useWallet", () => ({
  useWallet: () => ({
    wallet: {
      publicKey: "GDEPOSITOR12345678901234567890123456789012345678901234567890",
    },
  }),
}));

jest.mock("../src/theme/ThemeContext", () => ({
  useTheme: () => ({
    theme: {
      background: "#fff",
      surface: "#f7f7f7",
      border: "#ddd",
      textPrimary: "#111",
      textSecondary: "#444",
      textMuted: "#777",
      primary: "#111",
      link: "#06c",
      buttonPrimaryBg: "#111",
      buttonPrimaryText: "#fff",
      status: {
        error: "#f00",
        success: "#0a0",
        info: "#00f",
        warning: "#fa0",
      },
    },
  }),
}));

jest.mock("react-native-safe-area-context", () => ({
  SafeAreaView: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const mockedUseEscrowDetail = useEscrowDetail as jest.MockedFunction<typeof useEscrowDetail>;

const mockEscrow: EscrowDetail = {
  id: "escrow-123",
  depositor: "GDEPOSITOR12345678901234567890123456789012345678901234567890",
  beneficiary: "GBENEFICIARY123456789012345678901234567890123456789012345678",
  amount: "12500000",
  assetCode: "USDC",
  released: true,
  refunded: false,
  expiryLedger: 123456,
  expired: false,
  createdAt: "2026-10-12T08:30:00.000Z",
  expiresAt: 1_792_000_000,
  releasedAt: "2026-10-13T10:15:00.000Z",
};

function collectText(node: unknown): string[] {
  if (typeof node === "string" || typeof node === "number") return [String(node)];
  if (Array.isArray(node)) return node.flatMap(collectText);
  if (node && typeof node === "object") {
    const children = (node as { children?: unknown }).children;
    return collectText(children);
  }
  return [];
}

describe("<EscrowDetailScreen />", () => {
  beforeEach(() => {
    mockedUseEscrowDetail.mockReturnValue({
      state: { status: "success", detail: mockEscrow },
      refresh: jest.fn(async () => undefined),
    });
  });

  it("renders backend escrow details, counterparty, state and lifecycle timestamps", () => {
    let tree: renderer.ReactTestRenderer;
    renderer.act(() => {
      tree = renderer.create(<EscrowDetailScreen />);
    });

    const texts = collectText(tree!.toJSON());
    expect(texts.some((text) => text === "1.25")).toBe(true);
    expect(texts.some((text) => text === "USDC")).toBe(true);
    expect(texts.some((text) => text === "Released")).toBe(true);
    expect(texts.some((text) => text === "Counterparty")).toBe(true);
    expect(texts.some((text) => text === "Beneficiary")).toBe(true);
    expect(texts.some((text) => text === "Created")).toBe(true);
    expect(texts.some((text) => text === "Expires")).toBe(true);
    expect(texts.some((text) => text === "Released")).toBe(true);
    expect(texts.join(" ")).toContain("secure wallet signing");
    expect(mockedUseEscrowDetail).toHaveBeenCalledWith("escrow-123");
  });

  it("shows the backend expiry ledger when wall-clock timestamps are not present", () => {
    const summaryOnlyEscrow: EscrowDetail = {
      ...mockEscrow,
      createdAt: undefined,
      expiresAt: undefined,
      releasedAt: undefined,
    };
    mockedUseEscrowDetail.mockReturnValue({
      state: { status: "success", detail: summaryOnlyEscrow },
      refresh: jest.fn(async () => undefined),
    });

    let tree: renderer.ReactTestRenderer;
    renderer.act(() => {
      tree = renderer.create(<EscrowDetailScreen />);
    });

    const texts = collectText(tree!.toJSON());
    expect(texts).toContain("Expires at ledger");
    expect(texts).toContain("#123456");
  });

  it("shows a distinct not-found state for stale notification links", () => {
    mockedUseEscrowDetail.mockReturnValue({
      state: { status: "error", error: "Not found", notFound: true },
      refresh: jest.fn(async () => undefined),
    });

    let tree: renderer.ReactTestRenderer;
    renderer.act(() => {
      tree = renderer.create(<EscrowDetailScreen />);
    });

    const texts = collectText(tree!.toJSON());
    expect(texts.join(" ")).toContain("This escrow could not be found or has expired.");
    expect(texts).not.toContain("Retry");
  });
});
