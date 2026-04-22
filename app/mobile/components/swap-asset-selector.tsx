import React from 'react';
import {
  View,
  Text,
  Pressable,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { type PathPreviewRow } from '../services/link-metadata';
import { useTheme } from '../src/theme/ThemeContext';

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
  const { theme } = useTheme();

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
    return paths.sort(
      (a, b) =>
        Number(a.sourceAmount) - Number(b.sourceAmount) ||
        a.hopCount - b.hopCount,
    )[0];
  });

  if (loading) {
    return (
      <View style={styles.container}>
        <Text style={[styles.heading, { color: theme.textPrimary }]}>Select Payment Asset</Text>
        <View style={[styles.loadingContainer, { backgroundColor: theme.surface }]}>
          <ActivityIndicator size="large" color={theme.primary} />
          <Text style={[styles.loadingText, { color: theme.textSecondary }]}>Calculating exchange rates...</Text>
        </View>
      </View>
    );
  }

  if (!bestPaths || bestPaths.length === 0) {
    return (
      <View style={styles.container}>
        <Text style={[styles.heading, { color: theme.textPrimary }]}>Select Payment Asset</Text>
        <View style={[styles.emptyContainer, { backgroundColor: theme.surface }]}>
          <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
            Only direct payment with {destinationAsset} is available
          </Text>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={[styles.heading, { color: theme.textPrimary }]}>Select Payment Asset</Text>
      <Text style={[styles.subheading, { color: theme.textSecondary }]}>
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
                  { backgroundColor: theme.surface, borderColor: 'transparent' },
                  isSelected && { borderColor: theme.primary, backgroundColor: theme.surfaceElevated },
                ]}
                onPress={() => onSelectSourceAsset(path.sourceAsset, path)}
              >
                <View style={styles.optionHeader}>
                  <View style={styles.assetInfo}>
                    <Text style={[styles.optionAsset, { color: theme.textPrimary }]}>{path.sourceAsset}</Text>
                    <Text style={[styles.optionHops, { color: theme.textMuted }]}>{hopLabel}</Text>
                  </View>
                  <View style={styles.amountInfo}>
                    <Text style={[styles.sourceAmount, { color: theme.textPrimary }]}>
                      {path.sourceAmount}
                    </Text>
                    <Text style={[styles.sourceAssetLabel, { color: theme.textMuted }]}>
                      {path.sourceAsset}
                    </Text>
                  </View>
                </View>

                <View style={styles.rateContainer}>
                  <Text style={[styles.rateLabel, { color: theme.textMuted }]}>Rate:</Text>
                  <Text style={[styles.rateValue, { color: theme.textPrimary }]}>{path.rateDescription}</Text>
                </View>

                {isSelected && (
                  <View style={[styles.selectedCheckmark, { backgroundColor: theme.primary }]}>
                    <Text style={[styles.checkmarkText, { color: theme.primaryForeground }]}>✓</Text>
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
    marginBottom: 4,
  },
  subheading: {
    fontSize: 14,
    marginBottom: 16,
  },
  loadingContainer: {
    borderRadius: 16,
    padding: 32,
    alignItems: 'center',
    justifyContent: 'center',
  },
  loadingText: {
    fontSize: 14,
    marginTop: 12,
  },
  emptyContainer: {
    borderRadius: 16,
    padding: 20,
    alignItems: 'center',
  },
  emptyText: {
    fontSize: 14,
    textAlign: 'center',
  },
  optionsScroll: {
    maxHeight: 280,
  },
  optionsContainer: {
    gap: 12,
  },
  optionCard: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 2,
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
    marginBottom: 4,
  },
  optionHops: {
    fontSize: 12,
  },
  amountInfo: {
    alignItems: 'flex-end',
  },
  sourceAmount: {
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 2,
  },
  sourceAssetLabel: {
    fontSize: 12,
  },
  rateContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  rateLabel: {
    fontSize: 12,
  },
  rateValue: {
    fontSize: 12,
    fontWeight: '500',
  },
  selectedCheckmark: {
    position: 'absolute',
    top: 12,
    right: 12,
    width: 24,
    height: 24,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  checkmarkText: {
    fontSize: 14,
    fontWeight: '700',
  },
});
