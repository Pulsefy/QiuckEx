import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  Switch,
} from 'react-native';
import { useTheme } from '../hooks/useTheme';
import { themeTokens } from '../theme/tokens';
import { BuildMetadataPanel } from '../components/BuildMetadataPanel';

type ThemeOption = {
  value: 'system' | 'light' | 'dark';
  label: string;
  icon: string;
};

const THEME_OPTIONS: ThemeOption[] = [
  { value: 'system', label: 'System', icon: '🖥️' },
  { value: 'light', label: 'Light', icon: '☀️' },
  { value: 'dark', label: 'Dark', icon: '🌙' },
];

export function SettingsScreen() {
  const { mode, setMode, isDark, color, tokens } = useTheme();
  const [notifications, setNotifications] = React.useState(true);
  const [xrayDefault, setXrayDefault] = React.useState(false);

  const styles = themedStyles({ color, isDark, tokens });

  return (
    <ScrollView style={styles.container}>
      {/* Theme Section */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Appearance</Text>
        <View style={styles.themeSelector}>
          {THEME_OPTIONS.map((option) => (
            <TouchableOpacity
              key={option.value}
              style={[
                styles.themeOption,
                mode === option.value && styles.themeOptionActive,
              ]}
              onPress={() => setMode(option.value)}
              activeOpacity={0.8}
            >
              <Text style={styles.themeIcon}>{option.icon}</Text>
              <Text
                style={[
                  styles.themeLabel,
                  mode === option.value && styles.themeLabelActive,
                ]}
              >
                {option.label}
              </Text>
              {mode === option.value && (
                <View style={styles.checkmark}>
                  <Text style={styles.checkmarkText}>✓</Text>
                </View>
              )}
            </TouchableOpacity>
          ))}
        </View>
      </View>

      {/* Preferences Section */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Preferences</Text>
        
        <ToggleRow
          label="Push Notifications"
          description="Get alerts for incoming payments"
          value={notifications}
          onValueChange={setNotifications}
        />
        
        <View style={styles.divider} />
        
        <ToggleRow
          label="X-Ray by Default"
          description="Enable privacy shield for all links"
          value={xrayDefault}
          onValueChange={setXrayDefault}
        />
      </View>

      {/* Account Section */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Account</Text>
        
        <ActionRow label="Connected Wallet" value="G...ABC123" />
        <View style={styles.divider} />
        <ActionRow label="Username" value="@yourname" />
        <View style={styles.divider} />
        <ActionRow label="Network" value="Mainnet" />
      </View>

      {/* Danger Zone */}
      <View style={styles.dangerSection}>
        <TouchableOpacity style={styles.dangerButton}>
          <Text style={styles.dangerText}>Disconnect Wallet</Text>
        </TouchableOpacity>
      </View>

      {/* Build Metadata */}
      <BuildMetadataPanel />

      <Text style={styles.version}>QuickEx v2.3.0</Text>
    </ScrollView>
  );
}

function ToggleRow({
  label,
  description,
  value,
  onValueChange,
}: {
  label: string;
  description: string;
  value: boolean;
  onValueChange: (v: boolean) => void;
}) {
  const { color, tokens } = useTheme();
  
  return (
    <View style={toggleStyles.row}>
      <View style={toggleStyles.text}>
        <Text style={[toggleStyles.label, { color: color(tokens.text.primary) }]}>
          {label}
        </Text>
        <Text style={[toggleStyles.desc, { color: color(tokens.text.tertiary) }]}>
          {description}
        </Text>
      </View>
      <Switch
        value={value}
        onValueChange={onValueChange}
        trackColor={{
          false: color(tokens.border.default),
          true: color(tokens.action.primary),
        }}
        thumbColor={color(tokens.surface)}
        ios_backgroundColor={color(tokens.border.default)}
      />
    </View>
  );
}

const toggleStyles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 12,
  },
  text: {
    flex: 1,
    marginRight: 16,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 2,
  },
  desc: {
    fontSize: 13,
  },
});

function ActionRow({ label, value }: { label: string; value: string }) {
  const { color, tokens } = useTheme();
  
  return (
    <TouchableOpacity style={actionStyles.row} activeOpacity={0.7}>
      <Text style={[actionStyles.label, { color: color(tokens.text.primary) }]}>
        {label}
      </Text>
      <View style={actionStyles.right}>
        <Text
          style={[actionStyles.value, { color: color(tokens.text.secondary) }]}
          numberOfLines={1}
        >
          {value}
        </Text>
        <Text style={[actionStyles.chevron, { color: color(tokens.text.tertiary) }]}>
          ›
        </Text>
      </View>
    </TouchableOpacity>
  );
}

const actionStyles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 14,
  },
  label: {
    fontSize: 16,
    fontWeight: '500',
  },
  right: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  value: {
    fontSize: 15,
    maxWidth: 150,
  },
  chevron: {
    fontSize: 20,
    fontWeight: '400',
  },
});

function themedStyles({ color, isDark, tokens }: {
  color: (t: any) => string;
  isDark: boolean;
  tokens: typeof themeTokens;
}) {
  return StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: color(tokens.surface),
    },
    section: {
      marginTop: 24,
      paddingHorizontal: 20,
    },
    sectionTitle: {
      fontSize: 13,
      fontWeight: '700',
      color: color(tokens.text.secondary),
      textTransform: 'uppercase',
      letterSpacing: 1,
      marginBottom: 12,
    },
    themeSelector: {
      flexDirection: 'row',
      gap: 10,
    },
    themeOption: {
      flex: 1,
      alignItems: 'center',
      paddingVertical: 16,
      paddingHorizontal: 12,
      borderRadius: 16,
      backgroundColor: color(tokens.surfaceElevated),
      borderWidth: 2,
      borderColor: color(tokens.border.subtle),
    },
    themeOptionActive: {
      borderColor: color(tokens.action.primary),
      backgroundColor: color(tokens.state.selected),
    },
    themeIcon: {
      fontSize: 24,
      marginBottom: 8,
    },
    themeLabel: {
      fontSize: 14,
      fontWeight: '600',
      color: color(tokens.text.secondary),
    },
    themeLabelActive: {
      color: color(tokens.action.primary),
    },
    checkmark: {
      position: 'absolute',
      top: 8,
      right: 8,
      width: 20,
      height: 20,
      borderRadius: 10,
      backgroundColor: color(tokens.action.primary),
      alignItems: 'center',
      justifyContent: 'center',
    },
    checkmarkText: {
      color: color(tokens.text.inverse),
      fontSize: 12,
      fontWeight: '700',
    },
    divider: {
      height: 1,
      backgroundColor: color(tokens.border.subtle),
    },
    dangerSection: {
      marginTop: 32,
      paddingHorizontal: 20,
    },
    dangerButton: {
      paddingVertical: 16,
      borderRadius: 16,
      backgroundColor: color(tokens.state.error),
      alignItems: 'center',
    },
    dangerText: {
      fontSize: 16,
      fontWeight: '600',
      color: color(tokens.semantic.error),
    },
    version: {
      textAlign: 'center',
      marginTop: 24,
      marginBottom: 40,
      fontSize: 13,
      color: color(tokens.text.tertiary),
    },
  });
}