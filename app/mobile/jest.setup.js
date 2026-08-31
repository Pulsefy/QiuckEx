// Mock react-native-safe-area-context: replace SafeAreaView with a plain View
jest.mock("react-native-safe-area-context", () => ({
  SafeAreaView: ({ children, ...props }) => {
    const React = require("react");
    const { View } = require("react-native");
    return React.createElement(View, props, children);
  },
  useSafeAreaInsets: () => ({ top: 0, bottom: 0, left: 0, right: 0 }),
  SafeAreaProvider: ({ children }) => children,
}));

// Mock vector icons to avoid async font loading in tests
jest.mock("@expo/vector-icons", () => {
  return {
    Ionicons: ({ name, ...props }) => {
      const React = require("react");
      const { Text } = require("react-native");
      return React.createElement(Text, props, name);
    },
  };
});

jest.mock("expo-local-authentication", () => ({
  hasHardwareAsync: jest.fn(async () => true),
  isEnrolledAsync: jest.fn(async () => true),
  authenticateAsync: jest.fn(async () => ({ success: true })),
}));

jest.mock("expo-crypto", () => ({
  CryptoDigestAlgorithm: { SHA256: "SHA-256" },
  digestStringAsync: jest.fn(async (_algorithm, value) => `hashed:${value}`),
}));

jest.mock("expo-secure-store", () => {
  const store = {};
  return {
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: "WHEN_UNLOCKED_THIS_DEVICE_ONLY",
    isAvailableAsync: jest.fn(async () => true),
    getItemAsync: jest.fn(async (key) => store[key] ?? null),
    setItemAsync: jest.fn(async (key, value) => {
      store[key] = value;
    }),
    deleteItemAsync: jest.fn(async (key) => {
      delete store[key];
    }),
  };
});

jest.mock("expo-notifications", () => {
  const pushTokenListeners = new Set();
  return {
    getPermissionsAsync: jest.fn(async () => ({
      granted: true,
      status: "granted",
      canAskAgain: true,
      ios: { status: "granted", allowsBadge: true, allowsAlert: true, allowsSound: true },
    })),
    requestPermissionsAsync: jest.fn(async () => ({
      granted: true,
      status: "granted",
      canAskAgain: true,
      ios: { status: "granted", allowsBadge: true, allowsAlert: true, allowsSound: true },
    })),
    setBadgeCountAsync: jest.fn(async () => true),
    getExpoPushTokenAsync: jest.fn(async () => ({ data: "ExponentPushToken[test-token]" })),
    getDevicePushTokenAsync: jest.fn(async () => ({ data: "test-device-token" })),
    addPushTokenListener: jest.fn((listener) => {
      pushTokenListeners.add(listener);
      return {
        remove: () => pushTokenListeners.delete(listener),
      };
    }),
    __triggerPushTokenListener: (token) => {
      for (const listener of pushTokenListeners) listener({ data: token });
    },
    __listeners: pushTokenListeners,
  };
});

jest.mock("expo-background-task", () => ({
  BackgroundTaskResult: {
    Success: "Success",
    Failed: "Failed",
  },
  registerTaskAsync: jest.fn(async () => undefined),
  unregisterTaskAsync: jest.fn(async () => undefined),
}));

jest.mock("expo-task-manager", () => ({
  defineTask: jest.fn(),
  isTaskRegisteredAsync: jest.fn(async () => false),
}));

jest.mock("expo-battery", () => ({
  getBatteryLevelAsync: jest.fn(async () => 1),
}));
