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
