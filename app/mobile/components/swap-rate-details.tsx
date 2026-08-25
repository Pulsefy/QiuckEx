import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  TextInput,
  TouchableOpacity,
} from 'react-native';
import { calculateSlippage } from '../services/path-payment';
import type { PathPreviewRow } from '../services/link-metadata';
import { useTheme } from '../src/theme/ThemeContext';

interface SwapRateDetailsProps {
  swapPath: PathPreviewRow;
  destinationAsset: string;
  destinationAmount: string;
  timeRemaining: number;
  isExpired: boolean;
  onRefresh: () => void;
  slippageTolerance: number;
  onSlippageChange: (value: number) => void;
}

export function SwapRateDetails({
  swapPath,
  destinationAsset,
  destinationAmount,
  timeRemaining,
  isExpired,
  onRefresh,
  slippageTolerance,
  onSlippageChange,
}: SwapRateDetailsProps) {
  const { theme } = useTheme();
  const [showSlippageInput, setShowSlippageInput] = useState(false);
  const [localTolerance, setLocalTolerance] = useState(String(slippageTolerance));

  const estimatedSlippage = calculateSlippage(
    swapPath.sourceAmount,
    destinationAmount,
    swapPath.hopCount,
  );

  const slippagePercentage = (estimatedSlippage * 100).toFixed(2);
  const isSlippageHigh = estimatedSlippage > (slippageTolerance / 100);

  // Fee estimation: Stellar base fee (100 stroops = 0.00001 XLM) 
  // plus a small buffer for path payment operations
  const feeEstimate = '0.0001 XLM'; 

  const handleToleranceChange = (val: string) => {
    setLocalTolerance(val);
    const num = parseFloat(val);
    if (!isNaN(num) && num >= 0) {
      onSlippageChange(num);
    }
  };

  return (
    <View style={styles.container}>
      {/* Quote Expiry & Refresh */}
      <View
        style={[styles.expiryContainer, { backgroundColor: isExpired ? theme.status.errorBg : theme.surfaceElevated }]}
        accessibilityLabel={
          isExpired
            ? "Quote has expired. Please refresh the exchange rate quote before paying."
            : `Quote expires in ${Math.floor(timeRemaining / 60)} minutes and ${timeRemaining % 60} seconds. ${timeRemaining < 10 ? 'Warning: less than 10 seconds remaining.' : ''}`
        }
      >
        <View style={styles.expiryInfo} accessibilityElementsHidden={true} importantForAccessibility="no">
          <Text style={[styles.expiryLabel, { color: theme.textSecondary }]}>
            {isExpired ? 'Quote expired' : 'Quote expires in:'}
          </Text>
          {!isExpired && (
            <Text style={[styles.timer, { color: timeRemaining < 10 ? theme.status.error : theme.textPrimary }]}>
              {Math.floor(timeRemaining / 60)}:{String(timeRemaining % 60).padStart(2, '0')}
            </Text>
          )}
        </View>
        <TouchableOpacity
          style={[styles.refreshButton, { backgroundColor: theme.buttonPrimaryBg }]}
          onPress={onRefresh}
          accessibilityLabel={`Refresh exchange rate quote. Quote ${isExpired ? 'has expired' : `expires in ${Math.floor(timeRemaining / 60)}:${String(timeRemaining % 60).padStart(2, '0')}`}. Double-tap to request a fresh quote from the liquidity service.`}
          accessibilityRole="button"
          accessibilityHint="Refetches available liquidity and recalculates best rate"
        >
          <Text style={[styles.refreshButtonText, { color: theme.buttonPrimaryText }]} accessibilityElementsHidden={true} importantForAccessibility="no">Refresh Quote</Text>
        </TouchableOpacity>
      </View>

      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <View style={styles.sectionHeader}>
          <Text style={[styles.sectionLabel, { color: theme.textMuted }]} accessibilityRole="header">Exchange Details</Text>
          <View
            style={[styles.badge, { backgroundColor: theme.status.successBg }]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          >
            <Text style={[styles.badgeText, { color: theme.status.success }]}>Best Rate</Text>
          </View>
        </View>

        <View
          style={styles.detailRow}
          accessibilityLabel={`You pay maximum of ${swapPath.sourceAmount} ${swapPath.sourceAsset}. This includes slippage tolerance.`}
        >
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">You pay (Max):</Text>
          <Text style={[styles.detailValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">
            {swapPath.sourceAmount} {swapPath.sourceAsset}
          </Text>
        </View>

        <View
          style={styles.detailRow}
          accessibilityLabel={`They receive: exactly ${destinationAmount} ${destinationAsset}. Guaranteed final amount to recipient.`}
        >
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">They receive:</Text>
          <Text style={[styles.detailValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">
            {destinationAmount} {destinationAsset}
          </Text>
        </View>

        <View
          style={styles.detailRow}
          accessibilityLabel={`Stellar network fee estimate: ${feeEstimate}. Very small base fee for distributed ledger transaction.`}
        >
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Network Fee:</Text>
          <Text style={[styles.detailValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">{feeEstimate}</Text>
        </View>

        <View
          style={[styles.detailRow, styles.detailRowHighlight, { backgroundColor: theme.surfaceElevated }]}
          accessibilityLabel={`Exchange rate: ${swapPath.rateDescription}. Rate quote from liquidity orderbooks.`}
        >
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Rate:</Text>
          <Text style={[styles.rateValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">{swapPath.rateDescription}</Text>
        </View>
      </View>

      {/* Slippage Settings */}
      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <View style={styles.sectionHeader}>
          <Text style={[styles.sectionLabel, { color: theme.textMuted }]} accessibilityRole="header">Slippage Tolerance</Text>
          <TouchableOpacity
            onPress={() => setShowSlippageInput(!showSlippageInput)}
            accessibilityLabel={`${showSlippageInput ? 'Done adjusting slippage. Collapse advanced slippage controls.' : 'Adjust slippage tolerance. Show presets and custom input field.'}`}
            accessibilityRole="button"
            accessibilityState={{ expanded: showSlippageInput }}
          >
            <Text
              style={[styles.settingsLink, { color: theme.buttonPrimaryBg }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >
              {showSlippageInput ? 'Done' : 'Adjust'}
            </Text>
          </TouchableOpacity>
        </View>

        {showSlippageInput ? (
          <View style={styles.slippageInputContainer}>
            {['0.5', '1.0', '3.0'].map((val) => (
              <TouchableOpacity
                key={val}
                style={[
                  styles.presetButton,
                  String(slippageTolerance) === val && { backgroundColor: theme.buttonPrimaryBg },
                  { borderColor: theme.border }
                ]}
                onPress={() => handleToleranceChange(val)}
                accessibilityLabel={`Set slippage tolerance to ${val} percent. ${String(slippageTolerance) === val ? 'Currently selected.' : 'Not selected.'}.`}
                accessibilityRole="radio"
                accessibilityState={{ selected: String(slippageTolerance) === val }}
              >
                <Text
                  style={[
                    styles.presetText,
                    { color: String(slippageTolerance) === val ? theme.buttonPrimaryText : theme.textPrimary }
                  ]}
                  accessibilityElementsHidden={true}
                  importantForAccessibility="no"
                >
                  {val}%
                </Text>
              </TouchableOpacity>
            ))}
            <TextInput
              style={[styles.customInput, { color: theme.textPrimary, borderColor: theme.border }]}
              value={localTolerance}
              onChangeText={handleToleranceChange}
              keyboardType="decimal-pad"
              placeholder="Custom"
              placeholderTextColor={theme.textMuted}
              accessibilityLabel={`Custom slippage tolerance percent entry. Current value: ${localTolerance} percent.`}
              accessibilityHint="Enter a number to set a custom slippage tolerance percentage. High values reduce failure rate but cost more."
              accessibilityValue={{ text: `${localTolerance} percent` }}
            />
          </View>
        ) : (
          <View
            style={styles.slippageSummary}
            accessibilityLabel={`Estimated slippage: ~${slippagePercentage}%. Current tolerance: ${slippageTolerance}%. ${isSlippageHigh ? 'Warning: estimate exceeds tolerance. Tap Adjust to increase tolerance.' : 'Within acceptable tolerance.'}`}
          >
            <View style={[styles.slippageBar, { backgroundColor: theme.border }]} accessibilityElementsHidden={true} importantForAccessibility="no">
              <View
                style={[
                  styles.slippageFill,
                  {
                    width: `${Math.min(estimatedSlippage * 100, 100)}%`,
                    backgroundColor: isSlippageHigh ? theme.status.warning : theme.status.success,
                  },
                ]}
              />
            </View>
            <View style={styles.slippageTextRow} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.slippageText, { color: theme.textSecondary }]}>
                Est. Slippage: <Text style={{ fontWeight: '700' }}>~{slippagePercentage}%</Text>
              </Text>
              <Text style={[styles.slippageText, { color: theme.textSecondary }]}>
                Tolerance: <Text style={{ fontWeight: '700' }}>{slippageTolerance}%</Text>
              </Text>
            </View>
          </View>
        )}

        {isSlippageHigh && (
          <View
            style={[styles.warningContainer, { backgroundColor: theme.status.warningBg, marginTop: 12 }]}
            accessibilityLabel={`Slippage warning alert. Estimated slippage ${slippagePercentage} percent exceeds tolerance ${slippageTolerance} percent. Transaction may fail or result in poor rate. Consider tapping Adjust to increase tolerance.`}
            accessibilityRole="alert"
          >
            <Text style={styles.warningIcon} accessibilityElementsHidden={true} importantForAccessibility="no">⚠</Text>
            <View style={styles.warningContent} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.warningTitle, { color: theme.status.warning }]}>Slippage Warning</Text>
              <Text style={[styles.warningText, { color: theme.status.warning }]}>
                Estimated slippage ({slippagePercentage}%) exceeds your tolerance ({slippageTolerance}%).
                The transaction may fail or result in a poor rate.
              </Text>
            </View>
          </View>
        )}
      </View>

      {/* Path Breakdown */}
      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <Text style={[styles.sectionLabel, { color: theme.textMuted }]} accessibilityRole="header">Route Breakdown</Text>
        <View
          style={[styles.pathContainer, { backgroundColor: theme.surfaceElevated }]}
          accessibilityLabel={`Payment route: ${[swapPath.sourceAsset, ...swapPath.pathHops, destinationAsset].join(' → ')}. ${swapPath.hopCount === 0 ? 'Direct orderbook swap with no intermediaries.' : `${swapPath.hopCount} hop${swapPath.hopCount > 1 ? 's' : ''} through Stellar decentralized exchange.`}`}
        >
          <PathVisualization
            hops={swapPath.pathHops}
            sourceAsset={swapPath.sourceAsset}
            destinationAsset={destinationAsset}
          />
        </View>
        <Text
          style={[styles.pathInfo, { color: theme.textMuted }]}
          accessibilityElementsHidden={true}
          importantForAccessibility="no"
        >
          {swapPath.hopCount === 0
            ? 'Direct swap via orderbook'
            : `Optimized route through ${swapPath.hopCount} intermediary asset${swapPath.hopCount > 1 ? 's' : ''}`}
        </Text>
      </View>
    </View>
  );
}

function PathVisualization({
  hops,
  sourceAsset,
  destinationAsset,
}: {
  hops: string[];
  sourceAsset: string;
  destinationAsset: string;
}) {
  const { theme } = useTheme();
  const fullPath = [sourceAsset, ...hops, destinationAsset];

  return (
    <View style={styles.pathVisual} accessibilityElementsHidden={true} importantForAccessibility="no">
      {fullPath.map((asset, index) => (
        <React.Fragment key={`${asset}-${index}`}>
          <View style={[styles.pathStep, { backgroundColor: theme.background }]}>
            <Text style={[styles.pathStepText, { color: theme.textPrimary }]}>{asset}</Text>
          </View>
          {index < fullPath.length - 1 && (
            <Text style={[styles.pathArrow, { color: theme.textMuted }]}>→</Text>
          )}
        </React.Fragment>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    marginTop: 20,
    gap: 16,
  },
  expiryContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 12,
    borderRadius: 12,
    minHeight: 56,
  },
  expiryInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  expiryLabel: {
    fontSize: 14,
    fontWeight: '500',
  },
  timer: {
    fontSize: 16,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  refreshButton: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
    minHeight: 36,
    minWidth: 104,
    justifyContent: "center",
  },
  refreshButtonText: {
    fontSize: 12,
    fontWeight: '700',
  },
  section: {
    borderRadius: 12,
    padding: 16,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  sectionLabel: {
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 4,
  },
  badgeText: {
    fontSize: 10,
    fontWeight: '700',
  },
  detailRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 8,
  },
  detailRowHighlight: {
    marginHorizontal: -16,
    marginVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 8,
  },
  detailLabel: {
    fontSize: 13,
  },
  detailValue: {
    fontSize: 13,
    fontWeight: '600',
  },
  rateValue: {
    fontSize: 14,
    fontWeight: '700',
  },
  settingsLink: {
    fontSize: 12,
    fontWeight: '700',
  },
  slippageInputContainer: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 4,
  },
  presetButton: {
    flex: 1,
    height: 36,
    borderRadius: 8,
    borderWidth: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  presetText: {
    fontSize: 12,
    fontWeight: '600',
  },
  customInput: {
    flex: 1.5,
    height: 36,
    borderRadius: 8,
    borderWidth: 1,
    paddingHorizontal: 12,
    fontSize: 12,
  },
  slippageSummary: {
    marginTop: 4,
  },
  slippageTextRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 8,
  },
  pathContainer: {
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
  },
  pathVisual: {
    flexDirection: 'row',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 4,
  },
  pathStep: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
  },
  pathStepText: {
    fontSize: 11,
    fontWeight: '700',
  },
  pathArrow: {
    fontSize: 12,
  },
  pathInfo: {
    fontSize: 11,
    fontStyle: 'italic',
  },
  warningContainer: {
    flexDirection: 'row',
    borderRadius: 12,
    padding: 12,
    gap: 12,
    alignItems: 'flex-start',
    minHeight: 56,
  },
  warningIcon: {
    fontSize: 18,
    marginTop: 2,
  },
  warningContent: {
    flex: 1,
  },
  warningTitle: {
    fontSize: 13,
    fontWeight: '700',
    marginBottom: 4,
  },
  warningText: {
    fontSize: 12,
    lineHeight: 16,
  },
  slippageBar: {
    height: 6,
    borderRadius: 3,
    overflow: 'hidden',
  },
  slippageFill: {
    height: '100%',
    borderRadius: 3,
  },
  slippageText: {
    fontSize: 11,
  },
});
