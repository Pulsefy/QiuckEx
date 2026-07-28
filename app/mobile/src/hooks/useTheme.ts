import { useTheme as useThemeContext } from '../context/ThemeContext';
import { ColorToken } from '../theme/tokens';

/**
 * Enhanced theme hook with style generators
 */
export function useTheme() {
  const theme = useThemeContext();

  /**
   * Resolve a color token to current theme string
   */
  const color = (token: ColorToken): string => {
    return theme.resolve(token);
  };

  /**
   * Generate themed StyleSheet values
   */
  const themed = <T extends Record<string, any>>(
    styles: (theme: typeof theme) => T
  ): T => {
    return styles(theme);
  };

  return {
    ...theme,
    color,
    themed,
  };
}