import React from "react";
import render from "react-test-renderer";
import { ContractErrorState } from "../components/resilience/contract-error-state";
import { QuickexErrorCode } from "../utils/contract-error-mapper";

// Mock the ThemeContext
jest.mock("../src/theme/ThemeContext", () => ({
  useTheme: () => ({
    theme: {
      background: "#ffffff",
      surface: "#ffffff",
      divider: "#e5e7eb",
      textPrimary: "#111827",
      textSecondary: "#4b5563",
      textMuted: "#9ca3af",
      buttonPrimaryBg: "#3b82f6",
      buttonPrimaryText: "#ffffff",
      tint: "#2563eb",
      status: {
        error: "#dc2626",
        errorBg: "#fee2e2",
        warning: "#d97706",
        warningBg: "#fef3c7",
      },
    },
  }),
}));

// Mock ThemedText and ThemedView to act as standard React Native components
jest.mock("../components/themed-text", () => {
  const { Text } = require("react-native");
  return {
    ThemedText: ({ children, style, ...props }: any) => (
      <Text style={style} {...props}>
        {children}
      </Text>
    ),
  };
});

jest.mock("../components/themed-view", () => {
  const { View } = require("react-native");
  return {
    ThemedView: ({ children, style, ...props }: any) => (
      <View style={style} {...props}>
        {children}
      </View>
    ),
  };
});

// Helper function to collect all text values in a rendered tree
function collectText(node: any): string[] {
  if (typeof node === "string") return [node];
  if (Array.isArray(node)) return node.flatMap(collectText);
  if (node && typeof node === "object") {
    const n = node as Record<string, any>;
    return [
      ...collectText(n.children),
      ...(n.props ? collectText(n.props.children) : []),
    ];
  }
  return [];
}

describe("<ContractErrorState />", () => {
  it("renders correctly with a known contract error code", () => {
    // Code 308 (EscrowNotExpired) -> "Refund Locked"
    const onRetry = jest.fn();
    const onDismiss = jest.fn();

    let tree: render.ReactTestRenderer | null = null;
    render.act(() => {
      tree = render.create(
        <ContractErrorState
          error={QuickexErrorCode.EscrowNotExpired}
          onRetry={onRetry}
          onDismiss={onDismiss}
        />
      );
    });

    const texts = collectText(tree!.toJSON());
    expect(texts).toContain("Refund Locked");
    expect(texts).toContain(
      "You cannot claim a refund yet because the lockup expiration time has not been reached."
    );
    expect(texts).toContain("Wait for the lockup period to expire before requesting a refund.");
    expect(texts).toContain("Try Again Later");
    expect(texts).toContain("Dismiss");
    expect(texts).toContain("Code: 308");
  });

  it("calls onRetry when primary retry button is pressed", () => {
    const onRetry = jest.fn();
    let tree: render.ReactTestRenderer | null = null;

    render.act(() => {
      tree = render.create(
        <ContractErrorState
          error={QuickexErrorCode.EscrowNotExpired}
          onRetry={onRetry}
        />
      );
    });

    const primaryButton = tree!.root.findByProps({ testID: "error-primary-button" });
    render.act(() => {
      primaryButton.props.onPress();
    });

    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("calls onAction with actionType when primary button is pressed for other actions", () => {
    // Code 307 (EscrowExpired) -> actionType: "go_back"
    const onAction = jest.fn();
    let tree: render.ReactTestRenderer | null = null;

    render.act(() => {
      tree = render.create(
        <ContractErrorState
          error={QuickexErrorCode.EscrowExpired}
          onAction={onAction}
        />
      );
    });

    const primaryButton = tree!.root.findByProps({ testID: "error-primary-button" });
    render.act(() => {
      primaryButton.props.onPress();
    });

    expect(onAction).toHaveBeenCalledWith("go_back");
  });

  it("calls onDismiss when secondary button is pressed", () => {
    const onDismiss = jest.fn();
    let tree: render.ReactTestRenderer | null = null;

    render.act(() => {
      tree = render.create(
        <ContractErrorState
          error={QuickexErrorCode.EscrowNotExpired}
          onDismiss={onDismiss}
        />
      );
    });

    const secondaryButton = tree!.root.findByProps({ testID: "error-secondary-button" });
    render.act(() => {
      secondaryButton.props.onPress();
    });

    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});
