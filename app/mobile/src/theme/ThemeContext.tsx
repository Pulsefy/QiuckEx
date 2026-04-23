/**
 * Theme System v2 — Context & Provider (MOB-28)
 *
 * Supports four modes: light | dark | system | brand
 *   - `system` follows the device colour-scheme and resolves to light / dark.
 *   - `brand` requires a selected `brandThemeId`.
 *
 * Per-profile persistence is handled via AsyncStorage with the key pattern:
 *   `@quickex/theme/<profileId>`.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useColorScheme } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

import {
  type ThemeId,
  type ThemeMode,
  type ThemeTokens,
  LightTheme,
  DarkTheme,
  ThemeRegistry,
} from './tokens';

// ---------------------------------------------------------------------------
// 1. Persistence helpers
// ---------------------------------------------------------------------------

/** Build the AsyncStorage key for a given profile. */
function storageKey(profileId: string): string {
  return `@quickex/theme/${profileId}`;
}

export interface PersistedThemePreference {
  mode: ThemeMode;
  brandThemeId?: ThemeId;
}

async function loadPreference(
  profileId: string,
): Promise<PersistedThemePreference | null> {
  try {
    const raw = await AsyncStorage.getItem(storageKey(profileId));
    if (!raw) return null;
    return JSON.parse(raw) as PersistedThemePreference;
  } catch {
    return null;
  }
}

async function savePreference(
  profileId: string,
  preference: PersistedThemePreference,
): Promise<void> {
  try {
    await AsyncStorage.setItem(
      storageKey(profileId),
      JSON.stringify(preference),
    );
  } catch {
    // Swallow — preference will be re-read on next launch.
  }
}

// ---------------------------------------------------------------------------
// 2. Resolve mode → tokens
// ---------------------------------------------------------------------------

function resolveTheme(
  mode: ThemeMode,
  systemScheme: 'light' | 'dark',
  brandThemeId?: ThemeId,
): ThemeTokens {
  switch (mode) {
    case 'light':
      return LightTheme;
    case 'dark':
      return DarkTheme;
    case 'system':
      return systemScheme === 'dark' ? DarkTheme : LightTheme;
    case 'brand':
      if (brandThemeId && ThemeRegistry[brandThemeId]) {
        return ThemeRegistry[brandThemeId];
      }
      // Fallback to system if brandThemeId is somehow invalid.
      return systemScheme === 'dark' ? DarkTheme : LightTheme;
    default:
      return LightTheme;
  }
}

// ---------------------------------------------------------------------------
// 3. Context value
// ---------------------------------------------------------------------------

export interface ThemeContextValue {
  /** Resolved token set — use this for styling. */
  theme: ThemeTokens;
  /** Current mode the user selected. */
  mode: ThemeMode;
  /** Brand theme ID when mode === 'brand'. */
  brandThemeId: ThemeId | undefined;
  /** Change the active mode. */
  setMode: (mode: ThemeMode) => void;
  /** Select a brand theme (automatically switches mode to 'brand'). */
  setBrandTheme: (id: ThemeId) => void;
  /** Whether the final resolved theme is dark-based. */
  isDark: boolean;
  /** Whether the provider has finished loading persisted prefs. */
  isReady: boolean;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

// ---------------------------------------------------------------------------
// 4. Provider
// ---------------------------------------------------------------------------

export interface ThemeProviderProps {
  /** Defaults to "default" if not provided. */
  profileId?: string;
  children: React.ReactNode;
}

export function QuickExThemeProvider({
  profileId = 'default',
  children,
}: ThemeProviderProps) {
  const systemScheme = (useColorScheme() ?? 'light') as 'light' | 'dark';

  const [mode, setModeState] = useState<ThemeMode>('system');
  const [brandThemeId, setBrandThemeIdState] = useState<ThemeId | undefined>(
    undefined,
  );
  const [isReady, setIsReady] = useState(false);

  // ── Hydrate from AsyncStorage on mount ──
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const pref = await loadPreference(profileId);
      if (cancelled) return;
      if (pref) {
        setModeState(pref.mode);
        setBrandThemeIdState(pref.brandThemeId);
      }
      setIsReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [profileId]);

  // ── Public setters ────────────────────────────────────────────────────

  const setMode = useCallback(
    (next: ThemeMode) => {
      setModeState(next);
      // When switching away from brand, preserve last brandThemeId for UX.
      savePreference(profileId, { mode: next, brandThemeId });
    },
    [profileId, brandThemeId],
  );

  const setBrandTheme = useCallback(
    (id: ThemeId) => {
      setBrandThemeIdState(id);
      setModeState('brand');
      savePreference(profileId, { mode: 'brand', brandThemeId: id });
    },
    [profileId],
  );

  // ── Resolved theme ────────────────────────────────────────────────────

  const theme = useMemo(
    () => resolveTheme(mode, systemScheme, brandThemeId),
    [mode, systemScheme, brandThemeId],
  );

  const value: ThemeContextValue = useMemo(
    () => ({
      theme,
      mode,
      brandThemeId,
      setMode,
      setBrandTheme,
      isDark: theme.isDark,
      isReady,
    }),
    [theme, mode, brandThemeId, setMode, setBrandTheme, isReady],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// 5. Hook
// ---------------------------------------------------------------------------

/**
 * Access the resolved theme tokens from any component.
 *
 * @example
 * ```tsx
 * const { theme, isDark, setMode } = useTheme();
 * <View style={{ backgroundColor: theme.background }} />
 * ```
 */
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used within a <QuickExThemeProvider>');
  }
  return ctx;
}
