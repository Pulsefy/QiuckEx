import React, { useState, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  Switch,
} from 'react-native';
import { useTheme } from '../hooks/useTheme';
import { themeTokens } from '../theme/tokens';

export function PaymentScreen() {
  const { color, isDark, tokens } = useTheme();
  const [amount, setAmount] = useState('');
  const [memo, setMemo] = useState('');
  const [asset, setAsset] = useState<'USDC' | 'XLM'>('USDC');
  const [xrayEnabled, setXrayEnabled] = useState(false);

  const styles = themedStyles({ color, isDark, tokens });

  const handleGenerateLink = useCallback(() => {
    // Generate payment link logic
  }, [amount, memo, asset]);

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={styles.container}
    >
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Header */}
        <View style={styles.header}>
          <Text
            style={styles.headerTitle}
            accessibilityRole="header"
          >
            Create Payment Link
          </Text>
          <Text style={styles.headerSubtitle}>
            Generate an instant payment request
          </Text>
        </View>

        {/* Amount Input */}
        <View style={styles.inputGroup}>
          <Text
            style={styles.label}
            accessibilityRole="header"
          >
            Amount
          </Text>
          <View style={styles.amountContainer}>
            <View style={styles.assetSelector}>
              <TouchableOpacity
                style={[
                  styles.assetButton,
                  asset === 'USDC' && styles.assetButtonActive,
                ]}
                onPress={() => setAsset('USDC')}
                accessibilityLabel={`Select USDC asset${asset === 'USDC' ? ', selected' : ''}`}
                accessibilityRole="radio"
                accessibilityState={{ selected: asset === 'USDC' }}
                accessibilityHint="Tap to switch payment asset to USDC"
              >
                <Text
                  style={[
                    styles.assetText,
                    asset === 'USDC' && styles.assetTextActive,
                  ]}
                >
                  USDC
                </Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[
                  styles.assetButton,
                  asset === 'XLM' && styles.assetButtonActive,
                ]}
                onPress={() => setAsset('XLM')}
                accessibilityLabel={`Select XLM asset${asset === 'XLM' ? ', selected' : ''}`}
                accessibilityRole="radio"
                accessibilityState={{ selected: asset === 'XLM' }}
                accessibilityHint="Tap to switch payment asset to XLM"
              >
                <Text
                  style={[
                    styles.assetText,
                    asset === 'XLM' && styles.assetTextActive,
                  ]}
                >
                  XLM
                </Text>
              </TouchableOpacity>
            </View>
            <TextInput
              style={styles.amountInput}
              value={amount}
              onChangeText={setAmount}
              placeholder="0.00"
              placeholderTextColor={color(tokens.input.placeholder)}
              keyboardType="decimal-pad"
              selectionColor={color(tokens.action.primary)}
              accessibilityLabel={`Amount entry, current currency ${asset}`}
              accessibilityHint={`Enter ${asset} amount to request`}
              accessibilityValue={{
                text: amount ? `${amount} ${asset}` : `zero ${asset}`,
              }}
            />
          </View>
        </View>

        {/* Memo Input */}
        <View style={styles.inputGroup}>
          <Text
            style={styles.label}
            accessibilityRole="header"
          >
            Memo (optional)
          </Text>
          <TextInput
            style={styles.memoInput}
            value={memo}
            onChangeText={setMemo}
            placeholder="What's this for?"
            placeholderTextColor={color(tokens.input.placeholder)}
            multiline
            numberOfLines={3}
            selectionColor={color(tokens.action.primary)}
            accessibilityLabel={`Memo, optional${memo ? `, current value: ${memo}` : ''}`}
            accessibilityHint="Add an optional note to the payment request"
          />
        </View>

        {/* Privacy Toggle */}
        <View style={styles.privacyRow}>
          <View style={{ flex: 1, paddingRight: 16 }}>
            <Text
              style={styles.privacyTitle}
              accessibilityRole="header"
            >
              X-Ray Privacy
            </Text>
            <Text style={styles.privacyDesc}>
              Shield transaction details
            </Text>
          </View>
          <Switch
            value={xrayEnabled}
            onValueChange={setXrayEnabled}
            accessibilityLabel={`X-Ray Privacy, ${xrayEnabled ? 'enabled' : 'disabled'}`}
            accessibilityRole="switch"
            accessibilityState={{ checked: xrayEnabled }}
            accessibilityHint="Double-tap to toggle privacy shield for transaction details"
            trackColor={{
              false: color(tokens.border.default),
              true: color(tokens.action.primary),
            }}
            thumbColor={color(tokens.surface)}
            ios_backgroundColor={color(tokens.border.default)}
          />
        </View>

        {/* Generate Button */}
        <TouchableOpacity
          style={styles.generateButton}
          onPress={handleGenerateLink}
          activeOpacity={0.8}
          accessibilityLabel={`Generate payment link for ${amount || '0'} ${asset}`}
          accessibilityRole="button"
          accessibilityState={{ disabled: !amount }}
          accessibilityHint={amount ? 'Double-tap to create a payment request link' : 'Enter an amount first to enable generate'}
        >
          <Text style={styles.generateButtonText}>Generate Link</Text>
        </TouchableOpacity>

        {/* Info Footer */}
        <Text
          style={styles.footerText}
          accessibilityElementsHidden={true}
          importantForAccessibility="no-hide-descendants"
        >
          Payments settle in ~5 seconds on Stellar
        </Text>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

/**
 * Themed styles using token system
 */
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
    scrollContent: {
      padding: 20,
      paddingBottom: 40,
    },
    header: {
      marginBottom: 24,
    },
    headerTitle: {
      fontSize: 28,
      fontWeight: '700',
      color: color(tokens.text.primary),
      marginBottom: 4,
    },
    headerSubtitle: {
      fontSize: 16,
      color: color(tokens.text.secondary),
    },
    inputGroup: {
      marginBottom: 20,
    },
    label: {
      fontSize: 14,
      fontWeight: '600',
      color: color(tokens.text.secondary),
      marginBottom: 8,
      textTransform: 'uppercase',
      letterSpacing: 0.5,
    },
    amountContainer: {
      gap: 12,
    },
    assetSelector: {
      flexDirection: 'row',
      gap: 8,
      marginBottom: 12,
    },
    assetButton: {
      flex: 1,
      minHeight: 48,
      paddingVertical: 14,
      paddingHorizontal: 16,
      borderRadius: 12,
      backgroundColor: color(tokens.input.background),
      borderWidth: 1,
      borderColor: color(tokens.border.default),
      alignItems: 'center',
      justifyContent: 'center',
    },
    assetButtonActive: {
      backgroundColor: color(tokens.state.selected),
      borderColor: color(tokens.action.primary),
    },
    assetText: {
      fontSize: 16,
      fontWeight: '600',
      color: color(tokens.text.secondary),
    },
    assetTextActive: {
      color: color(tokens.action.primary),
    },
    amountInput: {
      fontSize: 48,
      fontWeight: '700',
      color: color(tokens.text.primary),
      textAlign: 'center',
      paddingVertical: 16,
      minHeight: 80,
      backgroundColor: color(tokens.input.background),
      borderRadius: 16,
      borderWidth: 2,
      borderColor: color(tokens.input.border),
    },
    memoInput: {
      fontSize: 16,
      color: color(tokens.text.primary),
      backgroundColor: color(tokens.input.background),
      borderRadius: 16,
      borderWidth: 1,
      borderColor: color(tokens.input.border),
      padding: 16,
      minHeight: 96,
      textAlignVertical: 'top',
    },
    privacyRow: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: 16,
      backgroundColor: color(tokens.surfaceElevated),
      borderRadius: 16,
      marginBottom: 20,
      borderWidth: 1,
      borderColor: color(tokens.border.subtle),
    },
    privacyTitle: {
      fontSize: 16,
      fontWeight: '600',
      color: color(tokens.text.primary),
      marginBottom: 2,
    },
    privacyDesc: {
      fontSize: 13,
      color: color(tokens.text.tertiary),
    },
    generateButton: {
      backgroundColor: color(tokens.action.primary),
      minHeight: 56,
      paddingVertical: 18,
      borderRadius: 16,
      alignItems: 'center',
      justifyContent: 'center',
      marginBottom: 16,
      shadowColor: color(tokens.action.primary),
      shadowOffset: { width: 0, height: 4 },
      shadowOpacity: isDark ? 0.3 : 0.2,
      shadowRadius: 12,
      elevation: 4,
    },
    generateButtonText: {
      fontSize: 18,
      fontWeight: '700',
      color: color(tokens.text.inverse),
    },
    footerText: {
      textAlign: 'center',
      fontSize: 13,
      color: color(tokens.text.tertiary),
    },
  });
}