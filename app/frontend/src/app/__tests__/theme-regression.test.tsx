import React, { useEffect } from "react";
import type { AnchorHTMLAttributes, ImgHTMLAttributes, ReactNode } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import PublicProfile from "@/app/[username]/page";
import AdminPage from "@/app/admin/page";
import Dashboard from "@/app/dashboard/page";
import Settings from "@/app/settings/page";
import { ThemeProvider, useTheme, type Theme } from "@/components/ThemeProvider";

vi.mock("next/navigation", () => ({
  useParams: () => ({ username: "alice" }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("next/image", () => ({
  default: ({ alt, ...props }: ImgHTMLAttributes<HTMLImageElement>) => <img alt={alt ?? ""} {...props} />,
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string; children: ReactNode }) => (
    <a href={href} {...props}>{children}</a>
  ),
}));

vi.mock("react-i18next", () => ({
  initReactI18next: { type: "3rdParty", init: () => undefined },
  useTranslation: () => ({
    t: (key: string, options?: Record<string, unknown>) => {
      if (options?.username) {
        return `${key}:${options.username}`;
      }
      if (key === "themeSettings") {
        return "Theme Settings";
      }
      if (key === "settingsTitle") {
        return "Settings";
      }
      if (key === "profileCustomization") {
        return "Profile Customization";
      }
      return key;
    },
  }),
}));

vi.mock("@/components/AnalyticsDashboard", () => ({
  default: () => <div data-testid="analytics-dashboard" />,
}));

vi.mock("@/components/NetworkBadge", () => ({
  NetworkBadge: () => <div data-testid="network-badge" />,
}));

vi.mock("@/components/LocaleSwitcher", () => ({
  LocaleSwitcher: () => <div data-testid="locale-switcher" />,
}));

vi.mock("@/hooks/useApi", () => ({
  useApi: () => ({
    data: { items: [] },
    error: null,
    loading: false,
    callApi: async (fn: () => Promise<unknown>) => fn(),
  }),
}));

vi.mock("@/hooks/analyticsApi", () => ({
  fetchAnalytics: async () => ({
    summary: {
      totalVolume: 1200,
      avgTxSize: 75,
      conversionRate: 92,
      totalTx: 44,
      successfulTx: 41,
      failedTx: 3,
      refundCount: 2,
    },
  }),
}));

vi.mock("@/hooks/marketplaceApi", () => ({
  fetchUserBids: async () => [],
  fetchUserListings: async () => [],
  formatCountdown: (value: string) => value,
}));

vi.mock("@/hooks/mockApi", () => ({
  mockContractCall: async () => undefined,
  mockFetch: async (payload: unknown) => payload,
}));

vi.mock("@/lib/api", () => ({
  getQuickexApiBase: () => "https://api.example.test",
}));

function ThemeHarness({ theme, children }: { theme: Theme; children: ReactNode }) {
  const { setTheme } = useTheme();

  useEffect(() => {
    setTheme(theme);
  }, [setTheme, theme]);

  return <>{children}</>;
}

function renderWithTheme(ui: ReactNode, theme: Theme) {
  return render(
    <ThemeProvider>
      <ThemeHarness theme={theme}>{ui}</ThemeHarness>
    </ThemeProvider>,
  );
}

function mockFetchResponses() {
  const fetchMock = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);

    if (url.includes("/health")) {
      return {
        ok: true,
        json: async () => ({ status: "ok", uptime: 120 }),
      };
    }

    if (url.includes("/admin/feature-flags")) {
      return {
        ok: true,
        json: async () => ({ flags: [], source: "cache", storeAvailable: true }),
      };
    }

    if (url.includes("/admin/audit")) {
      return {
        ok: true,
        json: async () => ({ data: [] }),
      };
    }

    return {
      ok: true,
      json: async () => ({}),
    };
  });

  vi.stubGlobal("fetch", fetchMock);
}

beforeEach(() => {
  mockFetchResponses();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("theme regression coverage", () => {
  it.each([
    { name: "public payment profile", ui: <PublicProfile />, assertion: /Send Payment/i, snapshotKey: "public-payment-profile" },
    { name: "dashboard", ui: <Dashboard />, assertion: /Welcome back\./i, snapshotKey: "dashboard" },
    { name: "settings", ui: <Settings />, assertion: /Theme Settings/i, snapshotKey: "settings" },
    { name: "admin", ui: <AdminPage />, assertion: /Safety Controls/i, snapshotKey: "admin" },
  ])("renders the $name surface in light and dark modes without regressions", async ({ ui, assertion, snapshotKey }) => {
    const lightView = renderWithTheme(ui, "light");
    await screen.findByText(assertion);

    await waitFor(() => {
      expect(document.documentElement.classList.contains("light")).toBe(true);
      expect(document.documentElement.classList.contains("dark")).toBe(false);
      expect(document.documentElement.style.colorScheme).toBe("light");
    });

    expect(lightView.container.firstChild).toMatchSnapshot(`${snapshotKey}-light`);

    cleanup();

    const darkView = renderWithTheme(ui, "dark");
    await waitFor(() => {
      expect(document.documentElement.classList.contains("dark")).toBe(true);
      expect(document.documentElement.classList.contains("light")).toBe(false);
      expect(document.documentElement.style.colorScheme).toBe("dark");
    });

    expect(darkView.container.firstChild).toMatchSnapshot(`${snapshotKey}-dark`);
  });
});
