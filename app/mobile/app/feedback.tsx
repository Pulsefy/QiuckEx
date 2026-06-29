import React, { useCallback, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Platform,
  Pressable,
  ScrollView,
  Share,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useRouter } from 'expo-router';

import { useTheme } from '../src/theme/ThemeContext';
import { useEnvironment } from '../contexts/EnvironmentContext';
import { useWallet } from '../hooks/useWallet';
import { getOfflineQueue } from '../services/offline-queue';
import { copyToClipboard } from '../src/utils/clipboard';
import {
  buildFeedbackMetadata,
  formatFeedbackForExport,
  submitFeedback,
  type FeedbackCategory,
  type FeedbackContext,
} from '../services/feedback';

const CATEGORIES: { value: FeedbackCategory; label: string }[] = [
  { value: 'bug', label: 'Bug' },
  { value: 'idea', label: 'Idea' },
  { value: 'question', label: 'Question' },
  { value: 'other', label: 'Other' },
];

export default function FeedbackScreen() {
  const { theme } = useTheme();
  const router = useRouter();
  const { currentId, current, metadata } = useEnvironment();
  const { wallet } = useWallet();

  const [category, setCategory] = useState<FeedbackCategory>('bug');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [attachLogs, setAttachLogs] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Screenshot attachment is a capture hook awaiting a bundled image picker;
  // until then no URIs are collected. Kept as a stable reference so the submit
  // path and preview already account for attachments.
  const screenshots = useMemo<string[]>(() => [], []);

  // Captured automatically — the contributor never types this. Memoised on the
  // values it derives from so the preview stays in sync as the environment or
  // wallet changes.
  const context = useMemo<FeedbackContext>(
    () => ({
      environmentId: currentId,
      environmentLabel: current.label,
      apiUrl: current.apiUrl,
      backendVersion: metadata?.appVersion,
      walletPublicKey: wallet.connected ? wallet.publicKey : undefined,
      platform: `${Platform.OS} ${Platform.Version ?? ''}`.trim(),
    }),
    [currentId, current, metadata, wallet],
  );

  const previewMetadata = useMemo(
    () => buildFeedbackMetadata(context),
    [context],
  );

  const canSubmit = title.trim().length > 0 && !submitting;

  // Optional log-export hook: pulls the offline queue as a redactable log dump.
  const collectLogs = useCallback(async (): Promise<string | undefined> => {
    if (!attachLogs) return undefined;
    try {
      const queue = await getOfflineQueue();
      return JSON.stringify(queue, null, 2);
    } catch {
      return undefined;
    }
  }, [attachLogs]);

  // Optional screenshot-attach hook. A native image picker isn't bundled in
  // this build, so attachment is gated behind availability; contributors can
  // still share exported context out-of-band. This keeps the capture surface
  // in place for when a picker is added.
  const handleAttachScreenshot = useCallback(() => {
    Alert.alert(
      'Attach Screenshot',
      'Screenshot capture is not available in this build. Use your device screenshot tool and attach it when sharing the exported feedback.',
    );
  }, []);

  const exportPayload = useCallback(
    async (text: string) => {
      try {
        await Share.share({ message: text }, { dialogTitle: 'Share Feedback' });
      } catch {
        // Fall back to clipboard if the share sheet is unavailable.
        const copied = await copyToClipboard(text);
        Alert.alert(
          copied ? 'Copied' : 'Export Failed',
          copied
            ? 'Feedback copied to clipboard.'
            : 'Could not export feedback.',
        );
      }
    },
    [],
  );

  const handleSubmit = useCallback(async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      const logs = await collectLogs();
      const result = await submitFeedback(
        {
          category,
          title,
          description,
          attachments: { screenshots, logs },
        },
        context,
      );

      if (result.status === 'submitted') {
        Alert.alert('Thanks!', 'Your feedback was sent.', [
          { text: 'OK', onPress: () => router.back() },
        ]);
        return;
      }

      // Couldn't reach the backend — offer the structured export instead.
      Alert.alert(
        'Saved for Export',
        `Couldn't reach the backend (${result.reason}). Share your feedback as a structured report instead?`,
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Share',
            onPress: () => exportPayload(formatFeedbackForExport(result.payload)),
          },
        ],
      );
    } finally {
      setSubmitting(false);
    }
  }, [
    canSubmit,
    collectLogs,
    category,
    title,
    description,
    screenshots,
    context,
    router,
    exportPayload,
  ]);

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
      edges={['top', 'bottom']}
    >
      <ScrollView
        contentContainerStyle={styles.content}
        keyboardShouldPersistTaps="handled"
      >
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Send Feedback
        </Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Report an issue or share an idea while testing. Build and environment
          details are attached automatically and sensitive values are redacted.
        </Text>

        <Text style={[styles.label, { color: theme.textPrimary }]}>Category</Text>
        <View style={styles.categoryRow}>
          {CATEGORIES.map((option) => {
            const active = option.value === category;
            return (
              <Pressable
                key={option.value}
                testID={`category-${option.value}`}
                onPress={() => setCategory(option.value)}
                style={[
                  styles.categoryChip,
                  {
                    backgroundColor: active
                      ? theme.chipActiveBg
                      : theme.surface,
                    borderColor: active
                      ? theme.buttonPrimaryBg
                      : theme.border,
                  },
                ]}
              >
                <Text
                  style={[
                    styles.categoryText,
                    {
                      color: active ? theme.chipActiveText : theme.textSecondary,
                    },
                  ]}
                >
                  {option.label}
                </Text>
              </Pressable>
            );
          })}
        </View>

        <Text style={[styles.label, { color: theme.textPrimary }]}>Title</Text>
        <TextInput
          testID="feedback-title"
          style={[
            styles.input,
            {
              backgroundColor: theme.surface,
              color: theme.textPrimary,
              borderColor: theme.border,
            },
          ]}
          placeholder="Short summary"
          placeholderTextColor={theme.textSecondary}
          value={title}
          onChangeText={setTitle}
          returnKeyType="next"
        />

        <Text style={[styles.label, { color: theme.textPrimary }]}>
          Description
        </Text>
        <TextInput
          testID="feedback-description"
          style={[
            styles.input,
            styles.textArea,
            {
              backgroundColor: theme.surface,
              color: theme.textPrimary,
              borderColor: theme.border,
            },
          ]}
          placeholder="What happened? What did you expect?"
          placeholderTextColor={theme.textSecondary}
          value={description}
          onChangeText={setDescription}
          multiline
          textAlignVertical="top"
        />

        <View
          style={[
            styles.optionRow,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <View style={styles.optionCopy}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>
              Attach diagnostic logs
            </Text>
            <Text style={[styles.helper, { color: theme.textMuted }]}>
              Includes the offline action queue. Redacted before sending.
            </Text>
          </View>
          <Switch value={attachLogs} onValueChange={setAttachLogs} />
        </View>

        <Pressable
          style={[
            styles.secondaryButton,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
          onPress={handleAttachScreenshot}
        >
          <Text style={[styles.secondaryButtonText, { color: theme.textPrimary }]}>
            {screenshots.length > 0
              ? `Screenshots attached (${screenshots.length})`
              : 'Attach screenshot'}
          </Text>
        </Pressable>

        <View
          style={[
            styles.metadataCard,
            {
              backgroundColor: theme.surfaceElevated,
              borderColor: theme.borderLight,
            },
          ]}
        >
          <Text style={[styles.metadataTitle, { color: theme.textSecondary }]}>
            Attached automatically
          </Text>
          <MetadataRow theme={theme} label="App version" value={previewMetadata.buildMetadata} />
          <MetadataRow
            theme={theme}
            label="Environment"
            value={`${context.environmentLabel} (${previewMetadata.network})`}
          />
          <MetadataRow theme={theme} label="API" value={previewMetadata.apiUrl} />
          {previewMetadata.backendVersion ? (
            <MetadataRow
              theme={theme}
              label="Backend"
              value={previewMetadata.backendVersion}
            />
          ) : null}
          {previewMetadata.walletPublicKeyMasked ? (
            <MetadataRow
              theme={theme}
              label="Wallet"
              value={previewMetadata.walletPublicKeyMasked}
            />
          ) : null}
          <MetadataRow theme={theme} label="Platform" value={previewMetadata.platform} />
        </View>

        <Pressable
          testID="feedback-submit"
          disabled={!canSubmit}
          style={[
            styles.submitButton,
            {
              backgroundColor: canSubmit ? theme.buttonPrimaryBg : theme.border,
            },
          ]}
          onPress={handleSubmit}
        >
          {submitting ? (
            <ActivityIndicator color={theme.buttonPrimaryText} />
          ) : (
            <Text
              style={[styles.submitText, { color: theme.buttonPrimaryText }]}
            >
              Send Feedback
            </Text>
          )}
        </Pressable>
      </ScrollView>
    </SafeAreaView>
  );
}

function MetadataRow({
  theme,
  label,
  value,
}: {
  theme: ReturnType<typeof useTheme>['theme'];
  label: string;
  value: string;
}) {
  return (
    <View style={styles.metadataRow}>
      <Text style={[styles.metadataLabel, { color: theme.textMuted }]}>
        {label}
      </Text>
      <Text
        style={[styles.metadataValue, { color: theme.textPrimary }]}
        numberOfLines={1}
      >
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: { padding: 24, gap: 14 },
  title: { fontSize: 28, fontWeight: '800' },
  subtitle: { fontSize: 15, lineHeight: 21 },
  label: { fontSize: 15, fontWeight: '700' },
  helper: { fontSize: 13, lineHeight: 18 },
  categoryRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  categoryChip: {
    borderWidth: 1,
    borderRadius: 999,
    paddingVertical: 8,
    paddingHorizontal: 16,
  },
  categoryText: { fontSize: 14, fontWeight: '600' },
  input: {
    borderRadius: 14,
    borderWidth: 1,
    padding: 14,
    fontSize: 16,
  },
  textArea: { minHeight: 120 },
  optionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
    gap: 12,
  },
  optionCopy: { flex: 1, gap: 4 },
  secondaryButton: {
    borderWidth: 1,
    borderRadius: 14,
    paddingVertical: 14,
    alignItems: 'center',
  },
  secondaryButtonText: { fontSize: 15, fontWeight: '600' },
  metadataCard: {
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
    gap: 10,
  },
  metadataTitle: {
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  metadataRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  metadataLabel: { fontSize: 13, fontWeight: '600' },
  metadataValue: { fontSize: 13, flexShrink: 1, fontFamily: 'Courier New' },
  submitButton: {
    borderRadius: 16,
    paddingVertical: 16,
    alignItems: 'center',
    marginTop: 8,
  },
  submitText: { fontSize: 16, fontWeight: '700' },
});
