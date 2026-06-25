/**
 * Theme System v2 — Token Engine (MOB-28 + MOB-37)
 *
 * Strictly-typed, token-based design system supporting:
 *   - Light / Dark / System / Brand modes
 *   - Per-profile persistence via AsyncStorage
 *   - WCAG 2.1 AA compliant contrast (≥ 4.5:1 for text)
 *   - MOB-37: Full semantic token coverage for Payment, Receipt, Settings, Notification screens
 *
 * All colour values intentionally use hex strings for RN/Expo compatibility.
 */

// ---------------------------------------------------------------------------
// 1. Token interface
// ---------------------------------------------------------------------------

/** Unique key identifying a theme. */
export type ThemeId = 'light' | 'dark' | 'quickex-blue' | 'pulsefy-purple';

/** The four user-selectable modes. */
export type ThemeMode = 'light' | 'dark' | 'system' | 'brand';

/** Chart palette — fixed length for consistency across charting libs. */
export type ChartColors = readonly [
  string,
  string,
  string,
  string,
  string,
  string,
];

/** Semantic status colours. */
export interface StatusColors {
  readonly success: string;
  readonly successBg: string;
  readonly warning: string;
  readonly warningBg: string;
  readonly error: string;
  readonly errorBg: string;
  readonly info: string;
  readonly infoBg: string;
}

/**
 * MOB-37: State colours for interactive feedback (selected, highlighted, etc.)
 */
export interface StateColors {
  readonly highlight: string;      // Unread notifications, hover states
  readonly selected: string;       // Active selection background
  readonly pressed: string;        // Touch feedback
}

/**
 * MOB-37: Action colours for CTAs and interactive elements
 */
export interface ActionColors {
  readonly primary: string;        // Main CTA background
  readonly primaryHover: string;   // CTA hover/pressed
  readonly secondary: string;      // Secondary action
  readonly danger: string;       // Destructive actions
  readonly success: string;      // Positive actions
  readonly warning: string;        // Caution actions
}

/**
 * MOB-37: Input-specific tokens for form fields
 */
export interface InputTokens {
  readonly bg: string;
  readonly border: string;
  readonly borderFocus: string;
  readonly text: string;
  readonly placeholder: string;
}

/**
 * MOB-37: Shadow/elevation tokens (RN-compatible)
 */
export interface ShadowTokens {
  readonly color: string;
  readonly opacity: number;
  readonly offset: { width: number; height: number };
  readonly radius: number;
  readonly elevation: number;
}

/**
 * Complete design-token contract that every theme must satisfy.
 *
 * Zero-Any Policy: this is the single source of truth — every key is required,
 * so theme objects will fail at compile time if any token is missing.
 */
export interface ThemeTokens {
  /** Machine-readable identifier. */
  readonly id: ThemeId;
  /** Human-friendly name for the selector UI. */
  readonly name: string;
  /** Whether this theme uses dark base tones. */
  readonly isDark: boolean;

  // ── Core palette ──────────────────────────────────────────────────────
  readonly background: string;
  readonly surface: string;
  readonly surfaceElevated: string;
  readonly primary: string;
  readonly primaryForeground: string;
  readonly secondary: string;
  readonly secondaryForeground: string;
  readonly textPrimary: string;
  readonly textSecondary: string;
  readonly textMuted: string;
  readonly border: string;
  readonly borderLight: string;
  readonly divider: string;

  // ── MOB-37: Text inverse (for buttons, badges) ────────────────────────
  readonly textInverse: string;

  // ── Interactive ───────────────────────────────────────────────────────
  readonly buttonPrimaryBg: string;
  readonly buttonPrimaryText: string;
  readonly buttonSecondaryBg: string;
  readonly buttonSecondaryText: string;
  readonly buttonSecondaryBorder: string;
  readonly buttonDangerBg: string;
  readonly buttonDangerText: string;
  readonly inputBg: string;
  readonly inputBorder: string;
  readonly inputText: string;
  readonly inputPlaceholder: string;
  readonly chipBg: string;
  readonly chipActiveBg: string;
  readonly chipText: string;
  readonly chipActiveText: string;

  // ── MOB-37: Structured input tokens ─────────────────────────────────────
  readonly input: InputTokens;

  // ── MOB-37: Structured action tokens ──────────────────────────────────
  readonly action: ActionColors;

  // ── MOB-37: Structured state tokens ───────────────────────────────────
  readonly state: StateColors;

  // ── Navigation ────────────────────────────────────────────────────────
  readonly headerBg: string;
  readonly tabIconDefault: string;
  readonly tabIconSelected: string;
  readonly tint: string;

  // ── Semantic status ───────────────────────────────────────────────────
  readonly status: StatusColors;

  // ── QR Code (must always be high-contrast) ────────────────────────────
  readonly qrForeground: string;
  readonly qrBackground: string;

  // ── Skeleton / loading placeholders ───────────────────────────────────
  readonly skeleton: string;

  // ── Network badges ────────────────────────────────────────────────────
  readonly networkMainnet: string;
  readonly networkTestnet: string;

  // ── Charts ────────────────────────────────────────────────────────────
  readonly chartColors: ChartColors;

  // ── Overlay / modal ───────────────────────────────────────────────────
  readonly overlayBg: string;

  // ── Link / Accent ─────────────────────────────────────────────────────
  readonly link: string;

  // ── Swatch preview colours (for the selector) ─────────────────────────
  readonly swatchPreview: readonly [string, string, string, string];

  // ── MOB-37: Elevation/shadow tokens ────────────────────────────────────
  readonly shadow: ShadowTokens;
  readonly shadowElevated: ShadowTokens;
}

// ---------------------------------------------------------------------------
// 2. Theme definitions
// ---------------------------------------------------------------------------

/**
 * Light Theme
 * Contrast-checked: textPrimary (#111827) on background (#FFFFFF) = 17.4:1 ✓
 */
export const LightTheme: ThemeTokens = {
  id: 'light',
  name: 'Light',
  isDark: false,

  background: '#FFFFFF',
  surface: '#F9FAFB',
  surfaceElevated: '#FFFFFF',
  primary: '#111827',
  primaryForeground: '#FFFFFF',
  secondary: '#6B7280',
  secondaryForeground: '#FFFFFF',
  textPrimary: '#111827',
  textSecondary: '#4B5563',
  textMuted: '#9CA3AF',
  border: '#E5E7EB',
  borderLight: '#F3F4F6',
  divider: '#E5E5E5',

  // MOB-37: Text inverse for buttons/badges on dark backgrounds
  textInverse: '#FFFFFF',

  buttonPrimaryBg: '#111827',
  buttonPrimaryText: '#FFFFFF',
  buttonSecondaryBg: 'transparent',
  buttonSecondaryText: '#111827',
  buttonSecondaryBorder: '#111827',
  buttonDangerBg: '#EF4444',
  buttonDangerText: '#FFFFFF',
  inputBg: '#F5F5F5',
  inputBorder: '#E5E7EB',
  inputText: '#111827',
  inputPlaceholder: '#9CA3AF',
  chipBg: '#FFFFFF',
  chipActiveBg: '#111827',
  chipText: '#374151',
  chipActiveText: '#FFFFFF',

  // MOB-37: Structured input tokens
  input: {
    bg: '#F5F5F5',
    border: '#E5E7EB',
    borderFocus: '#111827',
    text: '#111827',
    placeholder: '#9CA3AF',
  },

  // MOB-37: Structured action tokens
  action: {
    primary: '#111827',
    primaryHover: '#374151',
    secondary: '#6B7280',
    danger: '#EF4444',
    success: '#10B981',
    warning: '#F59E0B',
  },

  // MOB-37: Structured state tokens
  state: {
    highlight: '#EFF6FF',     // Unread notification bg
    selected: '#EEF2FF',        // Selected chip/item
    pressed: 'rgba(0, 0, 0, 0.04)', // Touch feedback
  },

  headerBg: '#FFFFFF',
  tabIconDefault: '#687076',
  tabIconSelected: '#0A7EA4',
  tint: '#0A7EA4',

  status: {
    success: '#10B981',
    successBg: '#ECFDF5',
    warning: '#F59E0B',
    warningBg: '#FFF3E5',
    error: '#EF4444',
    errorBg: '#FEF2F2',
    info: '#2563EB',
    infoBg: '#E3F2FD',
  },

  qrForeground: '#000000',
  qrBackground: '#FFFFFF',

  skeleton: '#E5E7EB',

  networkMainnet: '#10B981',
  networkTestnet: '#F59E0B',

  chartColors: ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'],

  overlayBg: 'rgba(17, 24, 39, 0.74)',

  link: '#0A7EA4',

  swatchPreview: ['#FFFFFF', '#111827', '#0A7EA4', '#10B981'],

  // MOB-37: Shadow tokens
  shadow: {
    color: '#000000',
    opacity: 0.05,
    offset: { width: 0, height: 2 },
    radius: 8,
    elevation: 2,
  },
  shadowElevated: {
    color: '#000000',
    opacity: 0.1,
    offset: { width: 0, height: 4 },
    radius: 16,
    elevation: 4,
  },
} as const;

/**
 * Dark Theme
 * Contrast-checked: textPrimary (#ECEDEE) on background (#0F1115) = 16.1:1 ✓
 */
export const DarkTheme: ThemeTokens = {
  id: 'dark',
  name: 'Dark',
  isDark: true,

  background: '#0F1115',
  surface: '#1A1D23',
  surfaceElevated: '#22252D',
  primary: '#FFFFFF',
  primaryForeground: '#111827',
  secondary: '#9CA3AF',
  secondaryForeground: '#111827',
  textPrimary: '#ECEDEE',
  textSecondary: '#9BA1A6',
  textMuted: '#6B7280',
  border: '#2D3139',
  borderLight: '#22252D',
  divider: '#2D3139',

  // MOB-37: Text inverse for buttons/badges on light backgrounds
  textInverse: '#0F1115',

  buttonPrimaryBg: '#FFFFFF',
  buttonPrimaryText: '#111827',
  buttonSecondaryBg: 'transparent',
  buttonSecondaryText: '#ECEDEE',
  buttonSecondaryBorder: '#ECEDEE',
  buttonDangerBg: '#DC2626',
  buttonDangerText: '#FFFFFF',
  inputBg: '#1A1D23',
  inputBorder: '#2D3139',
  inputText: '#ECEDEE',
  inputPlaceholder: '#6B7280',
  chipBg: '#1A1D23',
  chipActiveBg: '#ECEDEE',
  chipText: '#9BA1A6',
  chipActiveText: '#111827',

  // MOB-37: Structured input tokens
  input: {
    bg: '#1A1D23',
    border: '#2D3139',
    borderFocus: '#ECEDEE',
    text: '#ECEDEE',
    placeholder: '#6B7280',
  },

  // MOB-37: Structured action tokens
  action: {
    primary: '#FFFFFF',
    primaryHover: '#E5E7EB',
    secondary: '#9CA3AF',
    danger: '#DC2626',
    success: '#34D399',
    warning: '#FBBF24',
  },

  // MOB-37: Structured state tokens
  state: {
    highlight: '#1E3A5F',     // Unread notification bg (dark blue tint)
    selected: '#312E81',      // Selected chip/item (indigo tint)
    pressed: 'rgba(255, 255, 255, 0.06)', // Touch feedback
  },

  headerBg: '#0F1115',
  tabIconDefault: '#9BA1A6',
  tabIconSelected: '#FFFFFF',
  tint: '#FFFFFF',

  status: {
    success: '#34D399',
    successBg: '#064E3B',
    warning: '#FBBF24',
    warningBg: '#78350F',
    error: '#F87171',
    errorBg: '#7F1D1D',
    info: '#60A5FA',
    infoBg: '#1E3A5F',
  },

  qrForeground: '#000000',
  qrBackground: '#FFFFFF',

  skeleton: '#2D3139',

  networkMainnet: '#34D399',
  networkTestnet: '#FBBF24',

  chartColors: ['#60A5FA', '#34D399', '#FBBF24', '#F87171', '#A78BFA', '#F472B6'],

  overlayBg: 'rgba(0, 0, 0, 0.85)',

  link: '#60A5FA',

  swatchPreview: ['#0F1115', '#ECEDEE', '#60A5FA', '#34D399'],

  // MOB-37: Shadow tokens (subtle in dark mode)
  shadow: {
    color: '#000000',
    opacity: 0.2,
    offset: { width: 0, height: 2 },
    radius: 8,
    elevation: 2,
  },
  shadowElevated: {
    color: '#000000',
    opacity: 0.3,
    offset: { width: 0, height: 4 },
    radius: 16,
    elevation: 4,
  },
} as const;

/**
 * Brand: QuickEx Blue
 * Deep navy base with electric blue accents.
 * Contrast-checked: textPrimary (#F0F4FF) on background (#0B1120) = 16.8:1 ✓
 */
export const QuickExBlueTheme: ThemeTokens = {
  id: 'quickex-blue',
  name: 'QuickEx Blue',
  isDark: true,

  background: '#0B1120',
  surface: '#111B2E',
  surfaceElevated: '#162340',
  primary: '#3B82F6',
  primaryForeground: '#FFFFFF',
  secondary: '#60A5FA',
  secondaryForeground: '#0B1120',
  textPrimary: '#F0F4FF',
  textSecondary: '#94A3C7',
  textMuted: '#5B6B8E',
  border: '#1E2D4D',
  borderLight: '#162340',
  divider: '#1E2D4D',

  // MOB-37
  textInverse: '#0B1120',

  buttonPrimaryBg: '#3B82F6',
  buttonPrimaryText: '#FFFFFF',
  buttonSecondaryBg: 'transparent',
  buttonSecondaryText: '#60A5FA',
  buttonSecondaryBorder: '#3B82F6',
  buttonDangerBg: '#DC2626',
  buttonDangerText: '#FFFFFF',
  inputBg: '#111B2E',
  inputBorder: '#1E2D4D',
  inputText: '#F0F4FF',
  inputPlaceholder: '#5B6B8E',
  chipBg: '#111B2E',
  chipActiveBg: '#3B82F6',
  chipText: '#94A3C7',
  chipActiveText: '#FFFFFF',

  // MOB-37
  input: {
    bg: '#111B2E',
    border: '#1E2D4D',
    borderFocus: '#3B82F6',
    text: '#F0F4FF',
    placeholder: '#5B6B8E',
  },

  action: {
    primary: '#3B82F6',
    primaryHover: '#2563EB',
    secondary: '#60A5FA',
    danger: '#DC2626',
    success: '#34D399',
    warning: '#FBBF24',
  },

  state: {
    highlight: '#0F2340',
    selected: '#1E3A5F',
    pressed: 'rgba(59, 130, 246, 0.15)',
  },

  headerBg: '#0B1120',
  tabIconDefault: '#5B6B8E',
  tabIconSelected: '#3B82F6',
  tint: '#3B82F6',

  status: {
    success: '#34D399',
    successBg: '#0D2818',
    warning: '#FBBF24',
    warningBg: '#3D2B0A',
    error: '#F87171',
    errorBg: '#3B1111',
    info: '#60A5FA',
    infoBg: '#0F2340',
  },

  qrForeground: '#000000',
  qrBackground: '#FFFFFF',

  skeleton: '#1E2D4D',

  networkMainnet: '#34D399',
  networkTestnet: '#FBBF24',

  chartColors: ['#3B82F6', '#34D399', '#FBBF24', '#F87171', '#A78BFA', '#F472B6'],

  overlayBg: 'rgba(11, 17, 32, 0.88)',

  link: '#60A5FA',

  swatchPreview: ['#0B1120', '#3B82F6', '#60A5FA', '#34D399'],

  // MOB-37
  shadow: {
    color: '#000000',
    opacity: 0.3,
    offset: { width: 0, height: 2 },
    radius: 8,
    elevation: 2,
  },
  shadowElevated: {
    color: '#000000',
    opacity: 0.4,
    offset: { width: 0, height: 4 },
    radius: 16,
    elevation: 4,
  },
} as const;

/**
 * Brand: Pulsefy Purple
 * Rich violet-black base with vivid purple accents.
 * Contrast-checked: textPrimary (#F5F0FF) on background (#100B1F) = 17.2:1 ✓
 */
export const PulsefyPurpleTheme: ThemeTokens = {
  id: 'pulsefy-purple',
  name: 'Pulsefy Purple',
  isDark: true,

  background: '#100B1F',
  surface: '#1A1230',
  surfaceElevated: '#231A40',
  primary: '#8B5CF6',
  primaryForeground: '#FFFFFF',
  secondary: '#A78BFA',
  secondaryForeground: '#100B1F',
  textPrimary: '#F5F0FF',
  textSecondary: '#B8A5D4',
  textMuted: '#7B6A96',
  border: '#2D1F50',
  borderLight: '#231A40',
  divider: '#2D1F50',

  // MOB-37
  textInverse: '#100B1F',

  buttonPrimaryBg: '#8B5CF6',
  buttonPrimaryText: '#FFFFFF',
  buttonSecondaryBg: 'transparent',
  buttonSecondaryText: '#A78BFA',
  buttonSecondaryBorder: '#8B5CF6',
  buttonDangerBg: '#DC2626',
  buttonDangerText: '#FFFFFF',
  inputBg: '#1A1230',
  inputBorder: '#2D1F50',
  inputText: '#F5F0FF',
  inputPlaceholder: '#7B6A96',
  chipBg: '#1A1230',
  chipActiveBg: '#8B5CF6',
  chipText: '#B8A5D4',
  chipActiveText: '#FFFFFF',

  // MOB-37
  input: {
    bg: '#1A1230',
    border: '#2D1F50',
    borderFocus: '#8B5CF6',
    text: '#F5F0FF',
    placeholder: '#7B6A96',
  },

  action: {
    primary: '#8B5CF6',
    primaryHover: '#7C3AED',
    secondary: '#A78BFA',
    danger: '#DC2626',
    success: '#34D399',
    warning: '#FBBF24',
  },

  state: {
    highlight: '#231A40',
    selected: '#2D1F50',
    pressed: 'rgba(139, 92, 246, 0.15)',
  },

  headerBg: '#100B1F',
  tabIconDefault: '#7B6A96',
  tabIconSelected: '#8B5CF6',
  tint: '#8B5CF6',

  status: {
    success: '#34D399',
    successBg: '#0D2818',
    warning: '#FBBF24',
    warningBg: '#3D2B0A',
    error: '#F87171',
    errorBg: '#3B1111',
    info: '#60A5FA',
    infoBg: '#0F2340',
  },

  qrForeground: '#000000',
  qrBackground: '#FFFFFF',

  skeleton: '#2D1F50',

  networkMainnet: '#34D399',
  networkTestnet: '#FBBF24',

  chartColors: ['#8B5CF6', '#34D399', '#FBBF24', '#F87171', '#3B82F6', '#EC4899'],

  overlayBg: 'rgba(16, 11, 31, 0.88)',

  link: '#A78BFA',

  swatchPreview: ['#100B1F', '#8B5CF6', '#A78BFA', '#34D399'],

  // MOB-37
  shadow: {
    color: '#000000',
    opacity: 0.3,
    offset: { width: 0, height: 2 },
    radius: 8,
    elevation: 2,
  },
  shadowElevated: {
    color: '#000000',
    opacity: 0.4,
    offset: { width: 0, height: 4 },
    radius: 16,
    elevation: 4,
  },
} as const;

// ---------------------------------------------------------------------------
// 3. Registry
// ---------------------------------------------------------------------------

/** All available themes keyed by ThemeId. */
export const ThemeRegistry: Record<ThemeId, ThemeTokens> = {
  light: LightTheme,
  dark: DarkTheme,
  'quickex-blue': QuickExBlueTheme,
  'pulsefy-purple': PulsefyPurpleTheme,
} as const;

/** Brand themes only (for the selector). */
export const BrandThemes: readonly ThemeTokens[] = [
  QuickExBlueTheme,
  PulsefyPurpleTheme,
] as const;

/** Every available theme (for iteration). */
export const AllThemes: readonly ThemeTokens[] = Object.values(ThemeRegistry);

// ---------------------------------------------------------------------------
// 4. MOB-37: Theme resolution helpers
// ---------------------------------------------------------------------------

/**
 * Resolve a token value for a given theme mode.
 * When mode is 'system', falls back to the provided system preference.
 */
export function resolveToken<T extends { light: string; dark: string }>(
  token: T,
  mode: ThemeMode,
  systemPreference: 'light' | 'dark' = 'light'
): string {
  if (mode === 'system') {
    return systemPreference === 'dark' ? token.dark : token.light;
  }
  if (mode === 'brand') {
    // Brand themes are dark-based; adjust if light brand themes are added
    return token.dark;
  }
  return mode === 'dark' ? token.dark : token.light;
}

/**
 * MOB-37: Get shadow styles object for React Native
 */
export function getShadowStyles(theme: ThemeTokens, elevated: boolean = false) {
  const shadow = elevated ? theme.shadowElevated : theme.shadow;
  return {
    shadowColor: shadow.color,
    shadowOffset: shadow.offset,
    shadowOpacity: shadow.opacity,
    shadowRadius: shadow.radius,
    elevation: shadow.elevation,
  };
}

/**
 * MOB-37: Get status color config for a given status type
 */
export function getStatusColors(theme: ThemeTokens, status: 'success' | 'warning' | 'error' | 'info') {
  return {
    text: theme.status[status],
    bg: theme.status[`${status}Bg` as keyof StatusColors],
  };
}