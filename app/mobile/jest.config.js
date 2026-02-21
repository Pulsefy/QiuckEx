module.exports = {
    preset: 'jest-expo',
    moduleNameMapper: {
        // Stub out native modules that crash in the Jest/jsdom environment
        'react-native-safe-area-context': require.resolve(
            './__mocks__/react-native-safe-area-context.js'
        ),
    },
};
