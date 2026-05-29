import React, { useMemo, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useTheme } from '../src/theme/ThemeContext';
import { resolveDeepLink } from '../utils/deep-link-routing';
import * as Linking from 'expo-linking';

const EXAMPLE_LINKS = [
  'https://quickex.to/jordan?amount=12.5&asset=XLM',
  'quickex://transaction/tx_demo_12345?status=Success',
  'https://quickex.to/transaction/tx_demo_12345',
  'quickex://alice?amount=1.25&asset=USDC&privacy=true',
  'https://quickex.to/transaction/tx_demo_12345?memo=coffee',
];

export default function DeepLinkDebugScreen() {
  const { theme } = useTheme();
  const [input, setInput] = useState('');
  const result = useMemo(() => resolveDeepLink(input), [input]);

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]} edges={['top', 'bottom']}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={[styles.title, { color: theme.textPrimary }]}>Deep Link Debug</Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>Validate QuickEx deep link parsing and preview the target route.</Text>

        <TextInput
          style={[styles.input, { backgroundColor: theme.surface, color: theme.textPrimary, borderColor: theme.border }]}
          placeholder="Paste a deep link here"
          placeholderTextColor={theme.textSecondary}
          value={input}
          onChangeText={setInput}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          returnKeyType="done"
        />

        <View style={[styles.resultCard, { backgroundColor: theme.surface, borderColor: theme.border }]}> 
          <Text style={[styles.resultHeading, { color: theme.textPrimary }]}>Parsed Result</Text>
          {'route' in result ? (
            <>
              <Text style={[styles.resultLabel, { color: theme.textSecondary }]}>Target route</Text>
              <Text style={[styles.resultValue, { color: theme.textPrimary }]}>{result.route.pathname}</Text>
              <Text style={[styles.resultLabel, { color: theme.textSecondary }]}>Parameters</Text>
              <Text style={[styles.resultValue, { color: theme.textPrimary }]}>{JSON.stringify(result.route.params, null, 2)}</Text>
            </>
          ) : 'error' in result ? (
            <>
              <Text style={[styles.resultLabel, { color: theme.textSecondary }]}>Error</Text>
              <Text style={[styles.resultValue, { color: theme.textPrimary }]}>{result.error}</Text>
            </>
          ) : (
            <Text style={[styles.resultValue, { color: theme.textPrimary }]}>No QuickEx link detected.</Text>
          )}
        </View>

        <Text style={[styles.examplesTitle, { color: theme.textPrimary }]}>Example links</Text>
        {EXAMPLE_LINKS.map((example) => (
          <Pressable
            key={example}
            style={[styles.exampleButton, { backgroundColor: theme.buttonSecondaryBg }]}
            onPress={() => setInput(example)}
          >
            <Text style={[styles.exampleText, { color: theme.textSecondary }]} numberOfLines={1}> {example} </Text>
          </Pressable>
        ))}

        {input ? (
          <Pressable style={[styles.openButton, { backgroundColor: theme.buttonPrimaryBg }]} onPress={() => Linking.openURL(input)}>
            <Text style={[styles.openButtonText, { color: theme.buttonPrimaryText }]}>Open link</Text>
          </Pressable>
        ) : null}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: { padding: 24, gap: 16 },
  title: { fontSize: 28, fontWeight: '800' },
  subtitle: { fontSize: 16, lineHeight: 22 },
  input: {
    borderRadius: 16,
    borderWidth: 1,
    padding: 14,
    fontSize: 16,
  },
  resultCard: {
    borderRadius: 16,
    borderWidth: 1,
    padding: 16,
    gap: 12,
  },
  resultHeading: { fontSize: 18, fontWeight: '700' },
  resultLabel: { fontSize: 14, fontWeight: '600' },
  resultValue: { fontSize: 14, lineHeight: 20, fontFamily: 'Menlo' },
  examplesTitle: { fontSize: 16, fontWeight: '700', marginTop: 12 },
  exampleButton: {
    borderRadius: 14,
    paddingVertical: 12,
    paddingHorizontal: 14,
  },
  exampleText: { fontSize: 14 },
  openButton: {
    borderRadius: 16,
    paddingVertical: 14,
    alignItems: 'center',
  },
  openButtonText: { fontSize: 16, fontWeight: '700' },
});
