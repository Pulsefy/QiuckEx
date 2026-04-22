import React from 'react';
import {
  View,
  Text,
  StyleSheet,
} from 'react-native';
import { calculateSlippage } from '../services/path-payment';
import type { PathPreviewRow } from '../services/link-metadata';
import { useTheme } from '../src/theme/ThemeContext';

interface SwapRateDetailsProps {
  swapPath: PathPreviewRow;
  destinationAsset: string;
  destinationAmount: string;
}

export function SwapRateDetails({
  swapPath,
  destinationAsset,
  destinationAmount,
}: SwapRateDetailsProps) {
  const { theme } = useTheme();
  const slippage = calculateSlippage(
    swapPath.sourceAmount,
    destinationAmount,
    swapPath.hopCount,
  );

  const slippagePercentage = (slippage * 100).toFixed(2);
  const showSlippageWarning = slippage > 0.02; // Warn if slippage > 2%

  return (
    <View style={styles.container}>
      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <Text style={[styles.sectionLabel, { color: theme.textMuted }]}>Exchange Details</Text>
        
        <View style={styles.detailRow}>
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>You pay:</Text>
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

        <View style={[styles.detailRow, styles.detailRowHighlight, { backgroundColor: theme.surfaceElevated }]}>
          <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Rate:</Text>
          <Text style={[styles.rateValue, { color: theme.textPrimary }]}>{swapPath.rateDescription}</Text>
        </View>
      </View>

      {/* Path Information */}
      {swapPath.hopCount > 0 && (
        <View style={[styles.section, { backgroundColor: theme.surface }]}>
          <Text style={[styles.sectionLabel, { color: theme.textMuted }]}>Conversion Path</Text>
          <View style={[styles.pathContainer, { backgroundColor: theme.surfaceElevated }]}>
            <PathVisualization
              hops={swapPath.pathHops}
              sourceAsset={swapPath.sourceAsset}
              destinationAsset={destinationAsset}
            />
          </View>
          <Text style={[styles.pathInfo, { color: theme.textMuted }]}>
            {swapPath.hopCount === 1
              ? 'Converting through 1 intermediary asset'
              : `Converting through ${swapPath.hopCount} intermediary assets`}
          </Text>
        </View>
      )}

      {/* Slippage Warning */}
      {showSlippageWarning && (
        <View style={[styles.warningContainer, { backgroundColor: theme.status.warningBg }]}>
          <Text style={styles.warningIcon}>⚠</Text>
          <View style={styles.warningContent}>
            <Text style={[styles.warningTitle, { color: theme.status.warning }]}>Higher Slippage</Text>
            <Text style={[styles.warningText, { color: theme.status.warning }]}>
              Estimated slippage ~{slippagePercentage}%. Consider choosing a
              different asset or paying directly.
            </Text>
          </View>
        </View>
      )}

      {/* Slippage Info */}
      <View style={[styles.section, { backgroundColor: theme.surface }]}>
        <Text style={[styles.sectionLabel, { color: theme.textMuted }]}>Slippage</Text>
        <View style={[styles.slippageBar, { backgroundColor: theme.border }]}>
          <View
            style={[
              styles.slippageFill,
              {
                width: `${Math.min(slippage * 100, 100)}%`,
                backgroundColor: showSlippageWarning ? theme.status.warning : theme.status.success,
              },
            ]}
          />
        </View>
        <Text style={[styles.slippageText, { color: theme.textSecondary }]}>
          ~{slippagePercentage}% estimated slippage
        </Text>
      </View>

      {/* Best Practice Note */}
      <View style={[styles.noteContainer, { backgroundColor: theme.status.infoBg }]}>
        <Text style={[styles.noteText, { color: theme.status.info }]}>
          💡 Tip: Direct payments (0% slippage) are available with {destinationAsset}
        </Text>
      </View>
    </View>
  );
}

/**
 * Visualizes the conversion path (e.g., USDC → XLM → USD)
 */
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

  if (fullPath.length <= 2) {
    return (
      <Text style={[styles.directPath, { color: theme.textPrimary }]}>
        Direct: {sourceAsset} → {destinationAsset}
      </Text>
    );
  }

  return (
    <Text style={[styles.pathText, { color: theme.textSecondary }]} numberOfLines={2}>
      {fullPath.join(' → ')}
    </Text>
  );
}

const styles = StyleSheet.create({
  container: {
    marginTop: 20,
    gap: 16,
  },
  section: {
    borderRadius: 12,
    padding: 16,
  },
  sectionLabel: {
    fontSize: 13,
    fontWeight: '700',
    marginBottom: 12,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
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
  pathContainer: {
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
  },
  directPath: {
    fontSize: 13,
    fontWeight: '500',
  },
  pathText: {
    fontSize: 12,
    fontFamily: 'monospace',
    lineHeight: 18,
  },
  pathInfo: {
    fontSize: 12,
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
    marginBottom: 8,
  },
  slippageFill: {
    height: '100%',
    borderRadius: 3,
  },
  slippageText: {
    fontSize: 12,
  },
  noteContainer: {
    borderRadius: 12,
    padding: 12,
    marginTop: 8,
  },
  noteText: {
    fontSize: 12,
    fontWeight: '500',
  },
});
