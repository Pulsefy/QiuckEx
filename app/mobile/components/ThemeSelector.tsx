/**
 * Theme Selector — Visual swatch-based picker (MOB-28)
 *
 * Renders four mode options (Light, Dark, System, Brand) and, when Brand is
 * selected, shows swatch previews for each available brand theme.
 *
 * Designed for the Settings / Profile page.
 */

import React from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import {
  type ThemeMode,
  type ThemeTokens,
  BrandThemes,
  LightTheme,
  DarkTheme,
} from '../../src/theme/tokens';
import { useTheme } from '../../src/theme/ThemeContext';
import { useTranslation } from 'react-i18next';

type BrandTheme = (typeof BrandThemes)[number];

// ── Mode descriptions ───────────────────────────────────────────────────────

interface ModeOption {
  mode: ThemeMode;
  label: string;
  description: string;
  preview: ThemeTokens; // used for the mini-swatch
}

const MODE_OPTIONS: readonly ModeOption[] = [
  {
    mode: 'light',
    label: `☀️ ${t('lightMode')}`,
    description: t('lightModeDesc'),
    preview: LightTheme,
  },
  {
    mode: 'dark',
    label: `🌙 ${t('darkMode')}`,
    description: t('darkModeDesc'),
    preview: DarkTheme,
  },
  {
    mode: 'system',
    label: `⚙️ ${t('systemMode')}`,
    description: t('systemModeDesc'),
    preview: LightTheme, // placeholder, will adapt at runtime
  },
];

// ── Component ───────────────────────────────────────────────────────────────

export function ThemeSelector() {
  const { t } = useTranslation();
  const { theme, mode, brandThemeId, setMode, setBrandTheme } = useTheme();

  return (
    <View style={[styles.container, { backgroundColor: theme.surface, borderColor: theme.border }]}>
      <Text style={[styles.heading, { color: theme.textPrimary }]}>
        {t('appearance')}
      </Text>
      <Text style={[styles.subheading, { color: theme.textSecondary }]}>
        {t('chooseAppearance')}
      </Text>

      {/* ── Standard modes ─────────────────────────────────────────── */}
      <View style={styles.modesRow}>
        {MODE_OPTIONS.map((opt) => {
          const isActive = mode === opt.mode;
          return (
            <Pressable
              key={opt.mode}
              onPress={() => setMode(opt.mode)}
              style={[
                styles.modeCard,
                { backgroundColor: theme.surfaceElevated, borderColor: theme.border },
                isActive && { borderColor: theme.primary, borderWidth: 2 },
              ]}
              accessibilityLabel={`Select ${opt.label} theme`}
              accessibilityRole="button"
            >
              <MiniSwatch colors={opt.preview.swatchPreview} />
              <Text
                style={[
                  styles.modeLabel,
                  { color: theme.textPrimary },
                  isActive && { fontWeight: '800' },
                ]}
              >
                {opt.label}
              </Text>
              <Text style={[styles.modeDesc, { color: theme.textMuted }]} numberOfLines={1}>
                {opt.description}
              </Text>
              {isActive && (
                <View style={[styles.activeIndicator, { backgroundColor: theme.primary }]} />
              )}
            </Pressable>
          );
        })}
      </View>

      {/* ── Brand themes ───────────────────────────────────────────── */}
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Brand Themes
      </Text>

      <View style={styles.brandsRow}>
        {BrandThemes.map((brandTheme: BrandTheme) => {
          const isActive =
            mode === 'brand' && brandThemeId === brandTheme.id;
          return (
            <Pressable
              key={brandTheme.id}
              onPress={() => setBrandTheme(brandTheme.id)}
              style={[
                styles.brandCard,
                { backgroundColor: theme.surfaceElevated, borderColor: theme.border },
                isActive && { borderColor: brandTheme.primary, borderWidth: 2 },
              ]}
              accessibilityLabel={`Select ${brandTheme.name} brand theme`}
              accessibilityRole="button"
            >
              {/* Swatch preview */}
              <View style={styles.swatchRow}>
                {brandTheme.swatchPreview.map((color: string, i: number) => (
                  <View
                    key={i}
                    style={[
                      styles.swatchCircle,
                      { backgroundColor: color },
                      i === 0 && { borderWidth: 1, borderColor: theme.border },
                    ]}
                  />
                ))}
              </View>
              <Text
                style={[
                  styles.brandName,
                  { color: theme.textPrimary },
                  isActive && { color: brandTheme.primary, fontWeight: '800' },
                ]}
              >
                {brandTheme.name}
              </Text>
              {isActive && (
                <View style={[styles.activeIndicator, { backgroundColor: brandTheme.primary }]} />
              )}
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}

// ── Mini swatch (used inside the mode cards) ────────────────────────────────

function MiniSwatch({ colors }: { colors: readonly [string, string, string, string] }) {
  return (
    <View style={styles.miniSwatchRow}>
      {colors.map((c, i) => (
        <View key={i} style={[styles.miniSwatchDot, { backgroundColor: c }]} />
      ))}
    </View>
  );
}

// ── Styles ──────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
  },
  heading: {
    fontSize: 20,
    fontWeight: '700',
    marginBottom: 4,
  },
  subheading: {
    fontSize: 14,
    marginBottom: 20,
  },
  modesRow: {
    flexDirection: 'row',
    gap: 10,
    marginBottom: 24,
  },
  modeCard: {
    flex: 1,
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
    alignItems: 'center',
    gap: 6,
    position: 'relative',
    overflow: 'hidden',
  },
  modeLabel: {
    fontSize: 13,
    fontWeight: '700',
  },
  modeDesc: {
    fontSize: 10,
    textAlign: 'center',
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 12,
  },
  brandsRow: {
    flexDirection: 'row',
    gap: 12,
  },
  brandCard: {
    flex: 1,
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
    alignItems: 'center',
    gap: 10,
    position: 'relative',
    overflow: 'hidden',
  },
  swatchRow: {
    flexDirection: 'row',
    gap: 6,
  },
  swatchCircle: {
    width: 24,
    height: 24,
    borderRadius: 12,
  },
  brandName: {
    fontSize: 13,
    fontWeight: '600',
    textAlign: 'center',
  },
  activeIndicator: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: 3,
    borderBottomLeftRadius: 14,
    borderBottomRightRadius: 14,
  },
  miniSwatchRow: {
    flexDirection: 'row',
    gap: 4,
  },
  miniSwatchDot: {
    width: 14,
    height: 14,
    borderRadius: 7,
  },
});
