import React, { useState } from 'react';
import {
  View,
  Text,
  Pressable,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { type PathPreviewRow } from '../services/link-metadata';

interface SwapAssetSelectorProps {
  swapOptions: PathPreviewRow[];
  destinationAsset: string;
  destinationAmount: string;
  selectedSourceAsset: string | null;
  onSelectSourceAsset: (sourceAsset: string, path: PathPreviewRow) => void;
  loading?: boolean;
}

export function SwapAssetSelector({
  swapOptions,
  destinationAsset,
  destinationAmount,
  selectedSourceAsset,
  onSelectSourceAsset,
  loading = false,
}: SwapAssetSelectorProps) {
  // Group options by source asset
  const optionsBySourceAsset = swapOptions.reduce(
    (acc, option) => {
      const key = option.sourceAsset;
      if (!acc[key]) {
        acc[key] = [];
      }
      acc[key].push(option);
      return acc;
    },
    {} as Record<string, PathPreviewRow[]>,
  );

  // For each source asset, pick the best path (lowest source amount / fewest hops)
  const bestPaths = Object.entries(optionsBySourceAsset).map(([sourceAsset, paths]) => {
    // Sort by source amount (ascending) then by hop count (ascending)
    return paths.sort(
      (a, b) =>
        Number(a.sourceAmount) - Number(b.sourceAmount) ||
        a.hopCount - b.hopCount,
    )[0];
  });

  if (loading) {
    return (
      <View style={styles.container}>
        <Text style={styles.heading}>Select Payment Asset</Text>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#000" />
          <Text style={styles.loadingText}>Calculating exchange rates...</Text>
        </View>
      </View>
    );
  }

  if (!bestPaths || bestPaths.length === 0) {
    return (
      <View style={styles.container}>
        <Text style={styles.heading}>Select Payment Asset</Text>
        <View style={styles.emptyContainer}>
          <Text style={styles.emptyText}>
            Only direct payment with {destinationAsset} is available
          </Text>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.heading}>Select Payment Asset</Text>
      <Text style={styles.subheading}>
        You receive {destinationAmount} {destinationAsset}
      </Text>

      <ScrollView
        style={styles.optionsScroll}
        showsVerticalScrollIndicator={false}
        scrollEnabled={bestPaths.length > 3}
      >
        <View style={styles.optionsContainer}>
          {bestPaths.map((path, index) => {
            const isSelected = selectedSourceAsset === path.sourceAsset;
            const hopLabel =
              path.hopCount === 0
                ? 'Direct'
                : path.hopCount === 1
                  ? '1 intermediary'
                  : `${path.hopCount} intermediaries`;

            return (
              <Pressable
                key={`${path.sourceAsset}-${index}`}
                style={[
                  styles.optionCard,
                  isSelected && styles.optionCardSelected,
                ]}
                onPress={() => onSelectSourceAsset(path.sourceAsset, path)}
              >
                <View style={styles.optionHeader}>
                  <View style={styles.assetInfo}>
                    <Text style={styles.optionAsset}>{path.sourceAsset}</Text>
                    <Text style={styles.optionHops}>{hopLabel}</Text>
                  </View>
                  <View style={styles.amountInfo}>
                    <Text style={styles.sourceAmount}>
                      {path.sourceAmount}
                    </Text>
                    <Text style={styles.sourceAssetLabel}>
                      {path.sourceAsset}
                    </Text>
                  </View>
                </View>

                <View style={styles.rateContainer}>
                  <Text style={styles.rateLabel}>Rate:</Text>
                  <Text style={styles.rateValue}>{path.rateDescription}</Text>
                </View>

                {isSelected && (
                  <View style={styles.selectedCheckmark}>
                    <Text style={styles.checkmarkText}>✓</Text>
                  </View>
                )}
              </Pressable>
            );
          })}
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    marginTop: 24,
  },
  heading: {
    fontSize: 18,
    fontWeight: '700',
    color: '#000',
    marginBottom: 4,
  },
  subheading: {
    fontSize: 14,
    color: '#888',
    marginBottom: 16,
  },
  loadingContainer: {
    backgroundColor: '#F5F5F5',
    borderRadius: 16,
    padding: 32,
    alignItems: 'center',
    justifyContent: 'center',
  },
  loadingText: {
    fontSize: 14,
    color: '#888',
    marginTop: 12,
  },
  emptyContainer: {
    backgroundColor: '#F5F5F5',
    borderRadius: 16,
    padding: 20,
    alignItems: 'center',
  },
  emptyText: {
    fontSize: 14,
    color: '#888',
    textAlign: 'center',
  },
  optionsScroll: {
    maxHeight: 280,
  },
  optionsContainer: {
    gap: 12,
  },
  optionCard: {
    backgroundColor: '#F5F5F5',
    borderRadius: 12,
    padding: 16,
    borderWidth: 2,
    borderColor: 'transparent',
  },
  optionCardSelected: {
    borderColor: '#000',
    backgroundColor: '#FAFAFA',
  },
  optionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12,
  },
  assetInfo: {
    flex: 1,
  },
  optionAsset: {
    fontSize: 16,
    fontWeight: '700',
    color: '#000',
    marginBottom: 4,
  },
  optionHops: {
    fontSize: 12,
    color: '#888',
  },
  amountInfo: {
    alignItems: 'flex-end',
  },
  sourceAmount: {
    fontSize: 16,
    fontWeight: '700',
    color: '#000',
    marginBottom: 2,
  },
  sourceAssetLabel: {
    fontSize: 12,
    color: '#888',
  },
  rateContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  rateLabel: {
    fontSize: 12,
    color: '#888',
  },
  rateValue: {
    fontSize: 12,
    color: '#000',
    fontWeight: '500',
  },
  selectedCheckmark: {
    position: 'absolute',
    top: 12,
    right: 12,
    backgroundColor: '#000',
    width: 24,
    height: 24,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  checkmarkText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '700',
  },
});
