// @ts-nocheck
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { DeploymentDiagnosticsPanel } from "@/components/DeploymentDiagnosticsPanel";

// ---------------------------------------------------------------------------
// Mock navigator.clipboard
// ---------------------------------------------------------------------------

const writeTextMock = vi.fn().mockResolvedValue(undefined);

Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: { writeText: writeTextMock } },
  writable: true,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const originalEnv = process.env;

function setEnv(overrides: Record<string, string | undefined>) {
  process.env = { ...originalEnv, ...overrides };
}

beforeEach(() => {
  vi.useFakeTimers();
  writeTextMock.mockClear();
});

afterEach(() => {
  process.env = originalEnv;
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DeploymentDiagnosticsPanel", () => {
  it("renders the panel on a testnet preview deployment", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
      NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF: "feat/diagnostics",
      NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA:
        "abcdef1234567890abcdef1234567890abcdef12",
      NEXT_PUBLIC_QUICKEX_API_URL: "https://api-staging.quickex.to",
      NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION: "v2.3.1",
      NEXT_PUBLIC_APP_VERSION: "1.4.0-preview",
    });

    render(<DeploymentDiagnosticsPanel />);

    expect(
      screen.getByRole("region", { name: /preview deployment diagnostics/i }),
    ).toBeDefined();
    expect(screen.getByText("feat/diagnostics")).toBeDefined();
    expect(screen.getByText("https://api-staging.quickex.to")).toBeDefined();
    expect(screen.getByText("v2.3.1")).toBeDefined();
    expect(screen.getByText("1.4.0-preview")).toBeDefined();
  });

  it("renders nothing on mainnet + production Vercel (hidden from end users)", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "mainnet",
      NEXT_PUBLIC_VERCEL_ENV: "production",
    });

    const { container } = render(<DeploymentDiagnosticsPanel />);

    expect(container.firstChild).toBeNull();
  });

  it("renders the panel on mainnet + preview (mainnet branch preview)", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "mainnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
    });

    render(<DeploymentDiagnosticsPanel />);

    expect(
      screen.getByRole("region", { name: /preview deployment diagnostics/i }),
    ).toBeDefined();
  });

  it("shows 'not set' for missing optional values", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
    });

    // Clear any values that might bleed from other tests
    delete process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF;
    delete process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION;
    delete process.env.NEXT_PUBLIC_APP_VERSION;

    render(<DeploymentDiagnosticsPanel />);

    const notSetEls = screen.getAllByText("not set");
    expect(notSetEls.length).toBeGreaterThan(0);
  });

  it("displays the short commit SHA highlighted and the remainder dimmed", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
      NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA:
        "0123456789abcdef0123456789abcdef01234567",
    });

    render(<DeploymentDiagnosticsPanel />);

    // Short SHA (first 7 chars) should appear as its own text node
    expect(screen.getByText("0123456")).toBeDefined();
  });

  it("calls clipboard.writeText with the correct value when a row copy button is clicked", async () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
      NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF: "my-branch",
    });

    render(<DeploymentDiagnosticsPanel />);

    const branchCopyBtn = screen.getByRole("button", { name: /copy branch/i });
    fireEvent.click(branchCopyBtn);

    expect(writeTextMock).toHaveBeenCalledWith("my-branch");
  });

  it("shows '✓' feedback on the copy button after clicking, then reverts", async () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
      NEXT_PUBLIC_QUICKEX_API_URL: "https://api-staging.quickex.to",
    });

    render(<DeploymentDiagnosticsPanel />);

    const apiCopyBtn = screen.getByRole("button", { name: /copy api url/i });
    fireEvent.click(apiCopyBtn);

    expect(apiCopyBtn.textContent).toBe("✓");

    vi.advanceTimersByTime(2001);
    expect(apiCopyBtn.textContent).toBe("⧉");
  });

  it("copies all rows when 'Copy all' is clicked", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
      NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF: "feat/test",
      NEXT_PUBLIC_QUICKEX_API_URL: "https://api-staging.quickex.to",
    });

    render(<DeploymentDiagnosticsPanel />);

    const copyAllBtn = screen.getByRole("button", { name: /copy all diagnostics/i });
    fireEvent.click(copyAllBtn);

    expect(writeTextMock).toHaveBeenCalledTimes(1);
    const copied: string = writeTextMock.mock.calls[0][0];
    expect(copied).toContain("Branch: feat/test");
    expect(copied).toContain("API URL: https://api-staging.quickex.to");
  });

  it("disables copy button when value is not set", () => {
    setEnv({
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
      NEXT_PUBLIC_VERCEL_ENV: "preview",
    });
    delete process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF;

    render(<DeploymentDiagnosticsPanel />);

    const branchCopyBtn = screen.getByRole("button", { name: /copy branch/i });
    expect(branchCopyBtn).toHaveProperty("disabled", true);
  });
});
