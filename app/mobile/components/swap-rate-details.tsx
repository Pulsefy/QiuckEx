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
      <View style={[styles.expiryContainer, { backgroundColor: isExpired ? theme.status.errorBg : theme.surfaceElevated }]}>
        <View style={styles.expiryInfo}>
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
        >
          <Text style={[styles.refreshButtonText, { color: theme.buttonPrimaryText }]}>Refresh Quote</Text>
        </TouchableOpacity>
      </View>

      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <View style={styles.sectionHeader}>
          <Text style={[styles.sectionLabel, { color: theme.textMuted }]}>Exchange Details</Text>
          <View style={[styles.badge, { backgroundColor: theme.status.successBg }]}>
            <Text style={[styles.badgeText, { color: theme.status.success }]}>Best Rate</Text>
          </View>
        </View>
        
        <View style={styles.detailRow}>
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>You pay (Max):</Text>
          <Text style={[styles.detailValue, { color: theme.textPrimary }]}>
            {swapPath.sourceAmount} {swapPath.sourceAsset}
          </Text>
        </View>

        <View style={styles.detailRow}>
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>They receive:</Text>
          <Text style={[styles.detailValue, { color: theme.textPrimary }]}>
            {destinationAmount} {destinationAsset}
          </Text>
        </View>

        <View style={styles.detailRow}>
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Network Fee:</Text>
          <Text style={[styles.detailValue, { color: theme.textPrimary }]}>{feeEstimate}</Text>
        </View>

        <View style={[styles.detailRow, styles.detailRowHighlight, { backgroundColor: theme.surfaceElevated }]}>
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Rate:</Text>
          <Text style={[styles.rateValue, { color: theme.textPrimary }]}>{swapPath.rateDescription}</Text>
        </View>
      </View>

      {/* Slippage Settings */}
      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <View style={styles.sectionHeader}>
          <Text style={[styles.sectionLabel, { color: theme.textMuted }]}>Slippage Tolerance</Text>
          <TouchableOpacity onPress={() => setShowSlippageInput(!showSlippageInput)}>
            <Text style={[styles.settingsLink, { color: theme.buttonPrimaryBg }]}>
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
              >
                <Text style={[
                  styles.presetText,
                  { color: String(slippageTolerance) === val ? theme.buttonPrimaryText : theme.textPrimary }
                ]}>
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
            />
          </View>
        ) : (
          <View style={styles.slippageSummary}>
            <View style={[styles.slippageBar, { backgroundColor: theme.border }]}>
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
            <View style={styles.slippageTextRow}>
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
          <View style={[styles.warningContainer, { backgroundColor: theme.status.warningBg, marginTop: 12 }]}>
            <Text style={styles.warningIcon}>⚠</Text>
            <View style={styles.warningContent}>
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
        <Text style={[styles.sectionLabel, { color: theme.textMuted }]}>Route Breakdown</Text>
        <View style={[styles.pathContainer, { backgroundColor: theme.surfaceElevated }]}>
          <PathVisualization
            hops={swapPath.pathHops}
            sourceAsset={swapPath.sourceAsset}
            destinationAsset={destinationAsset}
          />
        </View>
        <Text style={[styles.pathInfo, { color: theme.textMuted }]}>
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
    <View style={styles.pathVisual}>
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
