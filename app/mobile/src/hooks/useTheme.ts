import { useTheme as useThemeContext } from '../theme/ThemeContext';
import { ColorToken, ThemeTokens } from '../theme/tokens';

/**
 * Enhanced theme hook with style generators
 */
export function useTheme() {
  const themeCtx = useThemeContext();
  const theme = themeCtx.theme;

  const enrichedTokens: ThemeTokens & {
    text: { primary: string; secondary: string; tertiary: string; inverse: string };
    border: { default: string; subtle: string };
    semantic: { error: string; errorBg: string; success: string; warning: string };
    state: typeof theme.state & { error: string };
  } = {
    ...theme,
    text: {
      primary: theme.textPrimary,
      secondary: theme.textSecondary,
      tertiary: theme.textMuted,
      inverse: theme.textInverse,
    },
    border: {
      default: theme.border,
      subtle: theme.borderLight,
    },
    semantic: {
      error: theme.status.error,
      errorBg: theme.status.errorBg,
      success: theme.status.success,
      warning: theme.status.warning,
    },
    state: {
      ...theme.state,
      error: theme.status.errorBg,
    },
  };

  /**
   * Resolve a color token to current theme string
   */
  const color = (token: ColorToken | any): string => {
    if (typeof token === 'string') return token;
    return String(token ?? '');
  };

  /**
   * Generate themed StyleSheet values
   */
  const themed = <T extends Record<string, any>>(
    stylesFn: (ctx: typeof themeCtx) => T
  ): T => {
    return stylesFn(themeCtx);
  };

  return {
    ...themeCtx,
    tokens: enrichedTokens,
    color,
    themed,
  };
}