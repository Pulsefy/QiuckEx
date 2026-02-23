// Mock react-native-safe-area-context: replace SafeAreaView with a plain View
jest.mock('react-native-safe-area-context', () => ({
    SafeAreaView: ({ children, ...props }) => {
        const React = require('react');
        const { View } = require('react-native');
        return React.createElement(View, props, children);
    },
    useSafeAreaInsets: () => ({ top: 0, bottom: 0, left: 0, right: 0 }),
    SafeAreaProvider: ({ children }) => children,
}));

// Mock vector icons to avoid async font loading in tests
jest.mock('@expo/vector-icons', () => {
    return {
        Ionicons: ({ name, ...props }) => {
            const React = require('react');
            const { Text } = require('react-native');
            return React.createElement(Text, props, name);
        },
    };
});
