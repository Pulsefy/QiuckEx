// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import MisconfigurationPage from "./page";
import { ENV_SPEC, RUNTIME_CONFIG_DOCS_URL } from "@/lib/env";

const originalEnv = process.env;

function setEnv(overrides: Record<string, string | undefined>) {
  process.env = { ...originalEnv, ...overrides };
}

afterEach(() => {
  cleanup();
  process.env = originalEnv;
});

describe("MisconfigurationPage (FE-71)", () => {
  it("names a missing required key and its expected shape", () => {
    setEnv({
      NEXT_PUBLIC_QUICKEX_API_URL: undefined,
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
    });
    render(<MisconfigurationPage />);

    expect(screen.getByText("NEXT_PUBLIC_QUICKEX_API_URL")).toBeTruthy();
    // Expected-shape guidance from the spec is shown.
    expect(
      screen.getByText(new RegExp(ENV_SPEC.NEXT_PUBLIC_QUICKEX_API_URL.expected, "i")),
    ).toBeTruthy();
  });

  it("reports an invalid value with the reason and expected shape", () => {
    setEnv({
      NEXT_PUBLIC_QUICKEX_API_URL: "https://api.example",
      NEXT_PUBLIC_STELLAR_NETWORK: "bogusnet",
    });
    render(<MisconfigurationPage />);

    expect(screen.getByText(/NEXT_PUBLIC_STELLAR_NETWORK/)).toBeTruthy();
    expect(
      screen.getAllByText(/testnet.*mainnet|mainnet.*testnet/i).length,
    ).toBeGreaterThan(0);
  });

  it("never renders the actual invalid value beyond the reason string", () => {
    // A secret-looking value must not leak into the DOM as a standalone token.
    setEnv({
      NEXT_PUBLIC_QUICKEX_API_URL: "not-a-url",
      NEXT_PUBLIC_STELLAR_NETWORK: "testnet",
    });
    const { container } = render(<MisconfigurationPage />);
    // The page shows the key name; it does not print a "value: <secret>" line.
    expect(container.textContent).not.toContain("NEXT_PUBLIC_QUICKEX_API_URL=");
  });

  it("links to the runtime config documentation", () => {
    setEnv({ NEXT_PUBLIC_QUICKEX_API_URL: undefined });
    render(<MisconfigurationPage />);
    const link = screen.getByRole("link", {
      name: /runtime configuration documentation/i,
    });
    expect(link.getAttribute("href")).toBe(RUNTIME_CONFIG_DOCS_URL);
  });
});
