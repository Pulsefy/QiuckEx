import React from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { QuickExThemeProvider as ThemeProvider, useTheme } from './theme/ThemeContext';
import { Slot as Navigation } from 'expo-router';

function ThemedStatusBar() {
  const { isDark } = useTheme();
  return <StatusBar style={isDark ? 'light' : 'dark'} />;
}

export default function App() {
  return (
    <SafeAreaProvider>
      <ThemeProvider>
        <ThemedStatusBar />
        <Navigation />
      </ThemeProvider>
    </SafeAreaProvider>
  );
}