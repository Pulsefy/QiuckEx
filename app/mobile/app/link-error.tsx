import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useRouter, useSearchParams } from 'expo-router';
import { useTheme } from '../src/theme/ThemeContext';

export default function LinkErrorScreen() {
  const router = useRouter();
  const { message, url } = useSearchParams();
  const { theme } = useTheme();

  const errorMessage =
    typeof message === 'string' && message.length > 0
      ? message
      : 'The link could not be opened. Please verify the link and try again.';
  const linkUrl = typeof url === 'string' ? url : undefined;

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]} edges={['top', 'bottom']}>
      <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}> 
        <Text style={[styles.title, { color: theme.textPrimary }]}>Unable to open link</Text>
        <Text style={[styles.message, { color: theme.textSecondary }]}>{errorMessage}</Text>
        {linkUrl ? (
          <View style={styles.linkRow}>
            <Text style={[styles.linkLabel, { color: theme.textSecondary }]}>Link:</Text>
            <Text style={[styles.linkValue, { color: theme.textPrimary }]} numberOfLines={2}>
              {linkUrl}
            </Text>
          </View>
        ) : null}
        <Pressable
          style={[styles.button, { backgroundColor: theme.buttonPrimaryBg }]}
          onPress={() => router.replace('/')}
        >
          <Text style={[styles.buttonText, { color: theme.buttonPrimaryText }]}>Return home</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', padding: 24 },
  card: { borderRadius: 20, borderWidth: 1, padding: 24, gap: 16 },
  title: { fontSize: 26, fontWeight: '700' },
  message: { fontSize: 16, lineHeight: 24 },
  linkRow: { gap: 8 },
  linkLabel: { fontSize: 14, fontWeight: '600' },
  linkValue: { fontSize: 14 },
  button: { marginTop: 12, borderRadius: 14, padding: 14, alignItems: 'center' },
  buttonText: { fontSize: 16, fontWeight: '700' },
});
