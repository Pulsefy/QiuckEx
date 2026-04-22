/**
 * Below are the colors that are used in the app. The colors are defined in the light and dark mode.
 * There are many other ways to style your app. For example, [Nativewind](https://www.nativewind.dev/), [Tamagui](https://tamagui.dev/), [unistyles](https://reactnativeunistyles.vercel.app), etc.
 *
 * DEPRECATED — prefer `src/theme/tokens.ts` and the `useTheme()` hook.
 * Kept for backwards-compatibility with existing ThemedText / ThemedView.
 */

import { Platform } from 'react-native';
import { LightTheme, DarkTheme } from '../src/theme/tokens';

const tintColorLight = LightTheme.tint;
const tintColorDark = DarkTheme.tint;

export const Colors = {
  light: {
    text: LightTheme.textPrimary,
    background: LightTheme.background,
    tint: tintColorLight,
    icon: LightTheme.tabIconDefault,
    tabIconDefault: LightTheme.tabIconDefault,
    tabIconSelected: tintColorLight,
  },
  dark: {
    text: DarkTheme.textPrimary,
    background: DarkTheme.background,
    tint: tintColorDark,
    icon: DarkTheme.tabIconDefault,
    tabIconDefault: DarkTheme.tabIconDefault,
    tabIconSelected: tintColorDark,
  },
};

export const Fonts = Platform.select({
  ios: {
    /** iOS `UIFontDescriptorSystemDesignDefault` */
    sans: 'system-ui',
    /** iOS `UIFontDescriptorSystemDesignSerif` */
    serif: 'ui-serif',
    /** iOS `UIFontDescriptorSystemDesignRounded` */
    rounded: 'ui-rounded',
    /** iOS `UIFontDescriptorSystemDesignMonospaced` */
    mono: 'ui-monospace',
  },
  default: {
    sans: 'normal',
    serif: 'serif',
    rounded: 'normal',
    mono: 'monospace',
  },
  web: {
    sans: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
    serif: "Georgia, 'Times New Roman', serif",
    rounded: "'SF Pro Rounded', 'Hiragino Maru Gothic ProN', Meiryo, 'MS PGothic', sans-serif",
    mono: "SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
  },
});
