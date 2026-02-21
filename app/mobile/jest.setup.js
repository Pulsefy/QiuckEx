const React = require('react');
const { View } = require('react-native');

// Mock react-native-safe-area-context: replace SafeAreaView with a plain View
jest.mock('react-native-safe-area-context', () => ({
    SafeAreaView: ({ children, ...props }) =>
        React.createElement(View, props, children),
    useSafeAreaInsets: () => ({ top: 0, bottom: 0, left: 0, right: 0 }),
    SafeAreaProvider: ({ children }) => children,
}));
