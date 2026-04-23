import React from "react";
import renderer, { act } from "react-test-renderer";

import HomeScreen from "../app/index";

jest.mock("expo-router", () => ({
  Link: ({ children }: { children: React.ReactNode }) => children,
  useRouter: () => ({ replace: jest.fn() }),
}));

jest.mock("../hooks/useOnboarding", () => ({
  useOnboarding: () => ({
    hasCompletedOnboarding: true,
    isLoading: false,
  }),
}));

jest.mock("../components/notifications/NotificationContext", () => ({
  useNotifications: () => ({
    currentAccountId:
      "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
    isSyncing: false,
    lastSyncedAt: Date.now(),
    recentActivity: [],
    syncNow: jest.fn(async () => undefined),
  }),
}));

jest.mock("../components/notifications/NotificationCenter", () => () => null);

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
      buttonSecondaryBorder: "#111",
      buttonSecondaryText: "#111",
    },
  }),
}));

describe("<HomeScreen />", () => {
  it("renders correctly", () => {
    let tree: renderer.ReactTestRenderer;

    act(() => {
      tree = renderer.create(<HomeScreen />);
    });

    expect(tree!.toJSON()).toBeDefined();
  });
});
