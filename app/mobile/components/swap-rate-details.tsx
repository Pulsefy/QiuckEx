import React from 'react';
import {
  View,
  Text,
  StyleSheet,
} from 'react-native';
import { calculateSlippage } from '../services/path-payment';
import type { PathPreviewRow } from '../services/link-metadata';

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
  const slippage = calculateSlippage(
    swapPath.sourceAmount,
    destinationAmount,
    swapPath.hopCount,
  );

  const slippagePercentage = (slippage * 100).toFixed(2);
  const showSlippageWarning = slippage > 0.02; // Warn if slippage > 2%

  return (
    <View style={styles.container}>
      <View style={styles.section}>
        <Text style={styles.sectionLabel}>Exchange Details</Text>
        
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>You pay:</Text>
          <Text style={styles.detailValue}>
            {swapPath.sourceAmount} {swapPath.sourceAsset}
          </Text>
        </View>

        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>They receive:</Text>
          <Text style={styles.detailValue}>
            {destinationAmount} {destinationAsset}
          </Text>
        </View>

        <View style={[styles.detailRow, styles.detailRowHighlight]}>
          <Text style={styles.detailLabel}>Rate:</Text>
          <Text style={styles.rateValue}>{swapPath.rateDescription}</Text>
        </View>
      </View>

      {/* Path Information */}
      {swapPath.hopCount > 0 && (
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Conversion Path</Text>
          <View style={styles.pathContainer}>
            <PathVisualization
              hops={swapPath.pathHops}
              sourceAsset={swapPath.sourceAsset}
              destinationAsset={destinationAsset}
            />
          </View>
          <Text style={styles.pathInfo}>
            {swapPath.hopCount === 1
              ? 'Converting through 1 intermediary asset'
              : `Converting through ${swapPath.hopCount} intermediary assets`}
          </Text>
        </View>
      )}

      {/* Slippage Warning */}
      {showSlippageWarning && (
        <View style={styles.warningContainer}>
          <Text style={styles.warningIcon}>⚠</Text>
          <View style={styles.warningContent}>
            <Text style={styles.warningTitle}>Higher Slippage</Text>
            <Text style={styles.warningText}>
              Estimated slippage ~{slippagePercentage}%. Consider choosing a
              different asset or paying directly.
            </Text>
          </View>
        </View>
      )}

      {/* Slippage Info */}
      <View style={styles.section}>
        <Text style={styles.sectionLabel}>Slippage</Text>
        <View style={styles.slippageBar}>
          <View
            style={[
              styles.slippageFill,
              {
                width: `${Math.min(slippage * 100, 100)}%`,
                backgroundColor: showSlippageWarning ? '#FF6B35' : '#4CAF50',
              },
            ]}
          />
        </View>
        <Text style={styles.slippageText}>
          ~{slippagePercentage}% estimated slippage
        </Text>
      </View>

      {/* Best Practice Note */}
      <View style={styles.noteContainer}>
        <Text style={styles.noteText}>
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
  const fullPath = [sourceAsset, ...hops, destinationAsset];

  if (fullPath.length <= 2) {
    return (
      <Text style={styles.directPath}>
        Direct: {sourceAsset} → {destinationAsset}
      </Text>
    );
  }

  return (
    <Text style={styles.pathText} numberOfLines={2}>
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
    backgroundColor: '#F5F5F5',
    borderRadius: 12,
    padding: 16,
  },
  sectionLabel: {
    fontSize: 13,
    fontWeight: '700',
    color: '#888',
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
    backgroundColor: '#EFEFEF',
    marginHorizontal: -16,
    marginVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 8,
  },
  detailLabel: {
    fontSize: 13,
    color: '#666',
  },
  detailValue: {
    fontSize: 13,
    fontWeight: '600',
    color: '#000',
  },
  rateValue: {
    fontSize: 14,
    fontWeight: '700',
    color: '#000',
  },
  pathContainer: {
    backgroundColor: '#EFEFEF',
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
  },
  directPath: {
    fontSize: 13,
    color: '#333',
    fontWeight: '500',
  },
  pathText: {
    fontSize: 12,
    color: '#555',
    fontFamily: 'monospace',
    lineHeight: 18,
  },
  pathInfo: {
    fontSize: 12,
    color: '#888',
    fontStyle: 'italic',
  },
  warningContainer: {
    flexDirection: 'row',
    backgroundColor: '#FFF3E5',
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
    color: '#FF6B35',
    marginBottom: 4,
  },
  warningText: {
    fontSize: 12,
    color: '#FF6B35',
    lineHeight: 16,
  },
  slippageBar: {
    height: 6,
    backgroundColor: '#E5E5E5',
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
    color: '#666',
  },
  noteContainer: {
    backgroundColor: '#E3F2FD',
    borderRadius: 12,
    padding: 12,
    marginTop: 8,
  },
  noteText: {
    fontSize: 12,
    color: '#1565C0',
    fontWeight: '500',
  },
});
