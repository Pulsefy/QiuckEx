import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  SafeAreaView,
  StatusBar,
  Share,
  Clipboard,
  ToastAndroid,
  Platform,
  LayoutAnimation,
  UIManager,
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { useTheme } from '../hooks/useTheme';
import { themeTokens } from '../theme/tokens';

// Enable LayoutAnimation on Android
if (Platform.OS === 'android' && UIManager.setLayoutAnimationEnabledExperimental) {
  UIManager.setLayoutAnimationEnabledExperimental(true);
}

// ---------------------------------------------------------------------------
// Types (MOB-41 v3)
// ---------------------------------------------------------------------------

type ReceiptStatus = 'success' | 'pending' | 'failed' | 'refund';

type TimelineStepStatus = 'completed' | 'current' | 'upcoming' | 'failed';

interface TimelineEvent {
  id: string;
  step: 'created' | 'submitted' | 'validated' | 'executed' | 'settled' | 'refunded';
  title: string;
  description: string;
  timestamp: string;
  status: TimelineStepStatus;
  txHash?: string;
}

interface ReceiptMetadata {
  receiptHash: string;
  createdAt: string;
  expiresAt?: string;
}

interface ContractMetadata {
  contractId: string;
  wasmHash: string;
  deployedAt: string;
  networkPassphrase: string;
}

interface NetworkMetadata {
  network: 'mainnet' | 'testnet' | 'futurenet';
  horizonUrl: string;
  ledger: number;
  ledgerCloseTime: string;
}

interface ReceiptData {
  id: string;
  amount: string;
  asset: string;
  sender: string;
  recipient: string;
  timestamp: string;
  status: ReceiptStatus;
  memo?: string;
  metadata: ReceiptMetadata;
  contract: ContractMetadata;
  network: NetworkMetadata;
  timeline: TimelineEvent[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncateHash(hash: string, start: number = 6, end: number = 6): string {
  if (hash.length <= start + end + 3) return hash;
  return `${hash.slice(0, start)}...${hash.slice(-end)}`;
}

function getExplorerUrl(receipt: ReceiptData): string {
  const baseUrl = receipt.network.network === 'mainnet'
    ? 'https://stellar.expert/explorer/public'
    : 'https://stellar.expert/explorer/testnet';
  return `${baseUrl}/tx/${receipt.metadata.receiptHash}`;
}

function generateSupportText(receipt: ReceiptData): string {
  const lines = [
    '=== QuickEx Payment Receipt ===',
    '',
    `Amount: ${receipt.amount} ${receipt.asset}`,
    `Status: ${receipt.status.toUpperCase()}`,
    `From: ${receipt.sender}`,
    `To: ${receipt.recipient}`,
    '',
    '--- Metadata ---',
    `Receipt Hash: ${receipt.metadata.receiptHash}`,
    `Contract ID: ${receipt.contract.contractId}`,
    `Network: ${receipt.network.network.toUpperCase()}`,
    `Ledger: ${receipt.network.ledger}`,
    `Timestamp: ${receipt.network.ledgerCloseTime}`,
    '',
    '--- Timeline ---',
    ...receipt.timeline.map((event) =>
      `[${event.status.toUpperCase()}] ${event.title} — ${event.timestamp}`
    ),
    '',
    `Explorer: ${getExplorerUrl(receipt)}`,
    '',
    'For support, include this entire message.',
    '===============================',
  ];
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Sub-Components
// ---------------------------------------------------------------------------

const STEP_ICONS: Record<string, string> = {
  created: '📝',
  submitted: '📤',
  validated: '✅',
  executed: '⚡',
  settled: '💰',
  refunded: '↩️',
};

const STEP_EMOJI: Record<TimelineStepStatus, string> = {
  completed: '✓',
  current: '⏳',
  upcoming: '○',
  failed: '✕',
};

const STEP_COLORS = {
  completed: { bg: '#10B981', text: '#FFFFFF' },
  current: { bg: '#F59E0B', text: '#FFFFFF' },
  upcoming: { bg: '#E5E7EB', text: '#9CA3AF' },
  failed: { bg: '#EF4444', text: '#FFFFFF' },
};

const NETWORK_CONFIG = {
  mainnet: { label: 'Mainnet', dot: '#10B981', bg: '#ECFDF5' },
  testnet: { label: 'Testnet', dot: '#F59E0B', bg: '#FFF3E5' },
  futurenet: { label: 'Futurenet', dot: '#8B5CF6', bg: '#F3E8FF' },
};

const STATUS_CONFIG = {
  success: {
    title: 'Payment Successful',
    subtitle: 'Funds have been settled to the recipient wallet.',
    icon: '✅',
    color: '#10B981',
  },
  pending: {
    title: 'Payment Pending',
    subtitle: 'Your transaction is being processed on the Stellar network.',
    icon: '⏳',
    color: '#F59E0B',
  },
  failed: {
    title: 'Payment Failed',
    subtitle: 'The transaction could not be completed. No funds were deducted.',
    icon: '❌',
    color: '#EF4444',
  },
  refund: {
    title: 'Payment Refunded',
    subtitle: 'Funds have been returned to your wallet.',
    icon: '↩️',
    color: '#8B5CF6',
  },
};

function NetworkBadge({ network, ledger }: { network: 'mainnet' | 'testnet' | 'futurenet'; ledger?: number }) {
  const { color, tokens } = useTheme();
  const config = NETWORK_CONFIG[network];

  return (
    <View style={[networkStyles.badge, { backgroundColor: config.bg }]}>
      <View style={[networkStyles.dot, { backgroundColor: config.dot }]} />
      <Text style={[networkStyles.label, { color: config.dot }]}>{config.label}</Text>
      {ledger !== undefined && (
        <Text style={[networkStyles.ledger, { color: color(tokens.textMuted) }]}>
          · Ledger {ledger.toLocaleString()}
        </Text>
      )}
    </View>
  );
}

const networkStyles = StyleSheet.create({
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 20,
    alignSelf: 'flex-start',
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 6,
  },
  label: {
    fontSize: 13,
    fontWeight: '700',
  },
  ledger: {
    fontSize: 12,
    marginLeft: 6,
  },
});

function TimelineNode({ event, isLast }: { event: TimelineEvent; isLast: boolean }) {
  const { color, tokens } = useTheme();
  const stepColor = STEP_COLORS[event.status];
  const isFailed = event.status === 'failed';

  return (
    <View style={timelineNodeStyles.container}>
      {!isLast && (
        <View
          style={[
            timelineNodeStyles.connector,
            {
              backgroundColor: isFailed
                ? '#EF4444'
                : event.status === 'completed'
                  ? '#10B981'
                  : color(tokens.border),
            },
          ]}
        />
      )}

      <View style={timelineNodeStyles.node}>
        <View style={[timelineNodeStyles.iconContainer, { backgroundColor: stepColor.bg }]}>
          <Text style={timelineNodeStyles.icon}>{STEP_ICONS[event.step] || '•'}</Text>
        </View>

        <View style={timelineNodeStyles.content}>
          <View style={timelineNodeStyles.titleRow}>
            <Text
              style={[
                timelineNodeStyles.title,
                {
                  color: isFailed ? '#EF4444' : color(tokens.textPrimary),
                  fontWeight: event.status === 'current' ? '700' : '600',
                },
              ]}
            >
              {event.title}
            </Text>
            <View style={[timelineNodeStyles.statusBadge, { backgroundColor: stepColor.bg }]}>
              <Text style={[timelineNodeStyles.statusText, { color: stepColor.text }]}>
                {STEP_EMOJI[event.status]}
              </Text>
            </View>
          </View>

          <Text style={[timelineNodeStyles.description, { color: color(tokens.textSecondary) }]}>
            {event.description}
          </Text>

          <View style={timelineNodeStyles.metaRow}>
            <Text style={[timelineNodeStyles.timestamp, { color: color(tokens.textMuted) }]}>
              {event.timestamp}
            </Text>
            {event.txHash && (
              <Text
                style={[timelineNodeStyles.txHash, { color: color(tokens.textMuted) }]}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {truncateHash(event.txHash, 8, 8)}
              </Text>
            )}
          </View>
        </View>
      </View>
    </View>
  );
}

const timelineNodeStyles = StyleSheet.create({
  container: {
    position: 'relative',
    paddingLeft: 20,
    paddingBottom: 0,
  },
  connector: {
    position: 'absolute',
    left: 27,
    top: 40,
    width: 2,
    height: '100%',
  },
  node: {
    flexDirection: 'row',
    alignItems: 'flex-start',
  },
  iconContainer: {
    width: 36,
    height: 36,
    borderRadius: 18,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
    zIndex: 1,
  },
  icon: {
    fontSize: 16,
  },
  content: {
    flex: 1,
    paddingTop: 2,
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 4,
  },
  title: {
    fontSize: 15,
    flex: 1,
    marginRight: 8,
  },
  statusBadge: {
    width: 22,
    height: 22,
    borderRadius: 11,
    alignItems: 'center',
    justifyContent: 'center',
  },
  statusText: {
    fontSize: 12,
    fontWeight: '700',
  },
  description: {
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 6,
  },
  metaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  timestamp: {
    fontSize: 12,
  },
  txHash: {
    fontSize: 11,
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    maxWidth: 120,
  },
});

function StatusTimeline({ events, status }: { events: TimelineEvent[]; status: ReceiptStatus }) {
  const { color, tokens } = useTheme();
  const config = STATUS_CONFIG[status];

  return (
    <View
      style={[
        statusTimelineStyles.container,
        { backgroundColor: color(tokens.surfaceElevated), borderColor: color(tokens.border) },
      ]}
    >
      <View
        style={[
          statusTimelineStyles.header,
          {
            backgroundColor: color(tokens.surface),
            borderBottomColor: color(tokens.border),
          },
        ]}
      >
        <View style={[statusTimelineStyles.statusIcon, { backgroundColor: `${config.color}20` }]}>
          <Text style={statusTimelineStyles.statusIconText}>{config.icon}</Text>
        </View>
        <View style={statusTimelineStyles.statusText}>
          <Text style={[statusTimelineStyles.statusTitle, { color: config.color }]}>
            {config.title}
          </Text>
          <Text style={[statusTimelineStyles.statusSubtitle, { color: color(tokens.textSecondary) }]}>
            {config.subtitle}
          </Text>
        </View>
      </View>

      <View style={statusTimelineStyles.timeline}>
        <Text
          style={[
            statusTimelineStyles.timelineTitle,
            { color: color(tokens.textMuted) },
          ]}
        >
          Transaction Timeline
        </Text>
        {events.map((event, index) => (
          <TimelineNode key={event.id} event={event} isLast={index === events.length - 1} />
        ))}
      </View>

      <View
        style={[
          statusTimelineStyles.supportHint,
          { backgroundColor: `${config.color}10` },
        ]}
      >
        <Text style={statusTimelineStyles.supportIcon}>💡</Text>
        <Text style={[statusTimelineStyles.supportText, { color: color(tokens.textSecondary) }]}>
          Having issues? Copy the receipt details below for support.
        </Text>
      </View>
    </View>
  );
}

const statusTimelineStyles = StyleSheet.create({
  container: {
    borderRadius: 16,
    borderWidth: 1,
    overflow: 'hidden',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 20,
    borderBottomWidth: 1,
  },
  statusIcon: {
    width: 48,
    height: 48,
    borderRadius: 24,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 16,
  },
  statusIconText: {
    fontSize: 24,
  },
  statusText: {
    flex: 1,
  },
  statusTitle: {
    fontSize: 18,
    fontWeight: '800',
    marginBottom: 4,
  },
  statusSubtitle: {
    fontSize: 14,
    lineHeight: 20,
  },
  timeline: {
    padding: 20,
    paddingTop: 16,
  },
  timelineTitle: {
    fontSize: 13,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 16,
  },
  supportHint: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    marginHorizontal: 16,
    marginBottom: 16,
    borderRadius: 12,
  },
  supportIcon: {
    fontSize: 16,
    marginRight: 10,
  },
  supportText: {
    flex: 1,
    fontSize: 13,
    lineHeight: 18,
  },
});

function MetadataSection({
  receiptMetadata,
  contract,
  network,
}: {
  receiptMetadata: ReceiptMetadata;
  contract: ContractMetadata;
  network: NetworkMetadata;
}) {
  const [expanded, setExpanded] = React.useState(false);
  const { color, tokens } = useTheme();

  const toggleExpand = () => {
    LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
    setExpanded(!expanded);
  };

  const copyToClipboard = (text: string, label: string) => {
    Clipboard.setString(text);
    if (Platform.OS === 'android') {
      ToastAndroid.show(`${label} copied`, ToastAndroid.SHORT);
    }
  };

  return (
    <View
      style={[
        metaStyles.container,
        { backgroundColor: color(tokens.surfaceElevated), borderColor: color(tokens.border) },
      ]}
    >
      <TouchableOpacity style={metaStyles.header} onPress={toggleExpand} activeOpacity={0.8}>
        <Text style={[metaStyles.headerTitle, { color: color(tokens.textPrimary) }]}>
          Transaction Details
        </Text>
        <Text style={[metaStyles.chevron, { color: color(tokens.textMuted) }]}>
          {expanded ? '▼' : '▶'}
        </Text>
      </TouchableOpacity>

      <View style={metaStyles.summary}>
        <View style={metaStyles.hashRow}>
          <Text style={[metaStyles.hashLabel, { color: color(tokens.textMuted) }]}>
            Receipt Hash
          </Text>
          <View style={metaStyles.hashValueRow}>
            <Text
              style={[
                metaStyles.hashValue,
                { color: color(tokens.textPrimary) },
              ]}
            >
              {truncateHash(receiptMetadata.receiptHash, 8, 8)}
            </Text>
            <TouchableOpacity
              style={[metaStyles.copyButton, { backgroundColor: color(tokens.surface) }]}
              onPress={() => copyToClipboard(receiptMetadata.receiptHash, 'Receipt hash')}
            >
              <Text>📋</Text>
            </TouchableOpacity>
          </View>
        </View>

        <NetworkBadge network={network.network} ledger={network.ledger} />

        <View style={metaStyles.timestampRow}>
          <Text style={[metaStyles.timestampLabel, { color: color(tokens.textMuted) }]}>
            Created
          </Text>
          <Text
            style={[metaStyles.timestampValue, { color: color(tokens.textSecondary) }]}
          >
            {receiptMetadata.createdAt}
          </Text>
        </View>
      </View>

      {expanded && (
        <View style={metaStyles.details}>
          <View style={[metaStyles.divider, { backgroundColor: color(tokens.border) }]} />

          <View style={metaStyles.section}>
            <Text style={[metaStyles.sectionTitle, { color: color(tokens.textMuted) }]}>
              Contract
            </Text>

            <View style={metaStyles.row}>
              <View style={metaStyles.labelValue}>
                <Text style={[metaStyles.label, { color: color(tokens.textMuted) }]}>
                  Contract ID
                </Text>
                <Text
                  style={[
                    metaStyles.value,
                    { color: color(tokens.textPrimary) },
                  ]}
                >
                  {truncateHash(contract.contractId)}
                </Text>
              </View>
              <TouchableOpacity
                style={[metaStyles.copyButton, { backgroundColor: color(tokens.surface) }]}
                onPress={() => copyToClipboard(contract.contractId, 'Contract ID')}
              >
                <Text>📋</Text>
              </TouchableOpacity>
            </View>

            <View style={[metaStyles.divider, { backgroundColor: color(tokens.border) }]} />

            <View style={metaStyles.row}>
              <View style={metaStyles.labelValue}>
                <Text style={[metaStyles.label, { color: color(tokens.textMuted) }]}>
                  WASM Hash
                </Text>
                <Text
                  style={[
                    metaStyles.value,
                    { color: color(tokens.textPrimary) },
                  ]}
                >
                  {truncateHash(contract.wasmHash)}
                </Text>
              </View>
              <TouchableOpacity
                style={[metaStyles.copyButton, { backgroundColor: color(tokens.surface) }]}
                onPress={() => copyToClipboard(contract.wasmHash, 'WASM hash')}
              >
                <Text>📋</Text>
              </TouchableOpacity>
            </View>

            <View style={[metaStyles.divider, { backgroundColor: color(tokens.border) }]} />

            <View style={metaStyles.row}>
              <View style={metaStyles.labelValue}>
                <Text style={[metaStyles.label, { color: color(tokens.textMuted) }]}>
                  Deployed
                </Text>
                <Text
                  style={[
                    metaStyles.value,
                    { color: color(tokens.textPrimary) },
                  ]}
                >
                  {contract.deployedAt}
                </Text>
              </View>
            </View>
          </View>

          <View style={[metaStyles.divider, { backgroundColor: color(tokens.border) }]} />

          <View style={metaStyles.section}>
            <Text style={[metaStyles.sectionTitle, { color: color(tokens.textMuted) }]}>
              Network
            </Text>
            <View style={metaStyles.row}>
              <View style={metaStyles.labelValue}>
                <Text style={[metaStyles.label, { color: color(tokens.textMuted) }]}>
                  Horizon URL
                </Text>
                <Text
                  style={[
                    metaStyles.value,
                    { color: color(tokens.textPrimary) },
                  ]}
                  numberOfLines={1}
                  ellipsizeMode="middle"
                >
                  {network.horizonUrl}
                </Text>
              </View>
            </View>
            <View style={metaStyles.row}>
              <View style={metaStyles.labelValue}>
                <Text style={[metaStyles.label, { color: color(tokens.textMuted) }]}>
                  Ledger Close
                </Text>
                <Text
                  style={[
                    metaStyles.value,
                    { color: color(tokens.textPrimary) },
                  ]}
                >
                  {network.ledgerCloseTime}
                </Text>
              </View>
            </View>
            <View style={metaStyles.row}>
              <View style={metaStyles.labelValue}>
                <Text style={[metaStyles.label, { color: color(tokens.textMuted) }]}>
                  Passphrase
                </Text>
                <Text
                  style={[
                    metaStyles.value,
                    { color: color(tokens.textPrimary) },
                  ]}
                  numberOfLines={1}
                  ellipsizeMode="middle"
                >
                  {contract.networkPassphrase}
                </Text>
              </View>
            </View>
          </View>

          {receiptMetadata.expiresAt && (
            <>
              <View style={[metaStyles.divider, { backgroundColor: color(tokens.border) }]} />
              <View
                style={[
                  metaStyles.expiryRow,
                  { backgroundColor: color(tokens.state.highlight) },
                ]}
              >
                <Text style={[metaStyles.expiryLabel, { color: color(tokens.status.warning) }]}>
                  ⏰ Expires
                </Text>
                <Text style={[metaStyles.expiryValue, { color: color(tokens.textPrimary) }]}>
                  {receiptMetadata.expiresAt}
                </Text>
              </View>
            </>
          )}
        </View>
      )}
    </View>
  );
}

const metaStyles = StyleSheet.create({
  container: {
    borderRadius: 16,
    borderWidth: 1,
    overflow: 'hidden',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 14,
  },
  headerTitle: {
    fontSize: 16,
    fontWeight: '700',
  },
  chevron: {
    fontSize: 12,
  },
  summary: {
    padding: 16,
    paddingTop: 0,
    gap: 12,
  },
  hashRow: {
    gap: 4,
  },
  hashLabel: {
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  hashValueRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  hashValue: {
    fontSize: 15,
    fontWeight: '700',
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
  },
  copyButton: {
    padding: 6,
    borderRadius: 6,
  },
  timestampRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  timestampLabel: {
    fontSize: 13,
  },
  timestampValue: {
    fontSize: 13,
    fontWeight: '500',
  },
  divider: {
    height: 1,
    marginHorizontal: 16,
  },
  details: {
    padding: 16,
    paddingTop: 0,
    gap: 16,
  },
  section: {
    gap: 12,
  },
  sectionTitle: {
    fontSize: 13,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 4,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  labelValue: {
    flex: 1,
  },
  label: {
    fontSize: 12,
    marginBottom: 2,
  },
  value: {
    fontSize: 14,
    fontWeight: '600',
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
  },
  expiryRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 8,
    marginHorizontal: -16,
    paddingHorizontal: 16,
    marginBottom: -16,
  },
  expiryLabel: {
    fontSize: 13,
    fontWeight: '600',
  },
  expiryValue: {
    fontSize: 13,
    fontWeight: '600',
  },
});

// ---------------------------------------------------------------------------
// Main Screen
// ---------------------------------------------------------------------------

export function ReceiptScreen({ receipt, onBack }: { receipt: ReceiptData; onBack?: () => void }) {
  const { color, tokens, isDark } = useTheme();

  const handleShare = async () => {
    try {
      await Share.share({
        title: `QuickEx Payment — ${receipt.amount} ${receipt.asset}`,
        message: generateSupportText(receipt),
        url: getExplorerUrl(receipt),
      }, {
        dialogTitle: 'Share Receipt',
        subject: `QuickEx Payment — ${receipt.amount} ${receipt.asset}`,
      });
    } catch (error) {
      // User cancelled
    }
  };

  const handleCopySupport = () => {
    Clipboard.setString(generateSupportText(receipt));
    if (Platform.OS === 'android') {
      ToastAndroid.show('Support info copied', ToastAndroid.SHORT);
    }
  };

  const handleViewExplorer = () => {
    const url = getExplorerUrl(receipt);
    // Open URL via Linking or pass to parent
  };

  const styles = themedStyles({ color, tokens, isDark });

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar barStyle={isDark ? 'light-content' : 'dark-content'} />

      {/* Header */}
      <View style={[styles.header, { borderBottomColor: color(tokens.border) }]}>
        <TouchableOpacity
          style={[styles.backButton, { backgroundColor: color(tokens.surfaceElevated) }]}
          onPress={onBack}
        >
          <Text style={[styles.backIcon, { color: color(tokens.textPrimary) }]}>←</Text>
        </TouchableOpacity>
        <Text style={[styles.headerTitle, { color: color(tokens.textPrimary) }]}>Receipt</Text>
        <TouchableOpacity
          style={[styles.shareButton, { backgroundColor: color(tokens.surfaceElevated) }]}
          onPress={handleShare}
        >
          <Text style={styles.shareIcon}>⬆️</Text>
        </TouchableOpacity>
      </View>

      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        {/* Amount Card */}
        <View
          style={[
            styles.amountCard,
            {
              backgroundColor: color(tokens.surfaceElevated),
              borderColor: color(tokens.border),
            },
          ]}
        >
          <Text style={[styles.amountLabel, { color: color(tokens.textSecondary) }]}>
            You {receipt.status === 'refund' ? 'received back' : receipt.status === 'success' ? 'sent' : 'are sending'}
          </Text>
          <View style={styles.amountRow}>
            <Text style={[styles.amountValue, { color: color(tokens.textPrimary) }]}>
              {receipt.amount}
            </Text>
            <Text style={[styles.amountAsset, { color: color(tokens.textSecondary) }]}>
              {receipt.asset}
            </Text>
          </View>
          <View style={styles.partiesRow}>
            <View style={styles.party}>
              <Text style={[styles.partyLabel, { color: color(tokens.textMuted) }]}>From</Text>
              <Text
                style={[styles.partyValue, { color: color(tokens.textPrimary) }]}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {receipt.sender}
              </Text>
            </View>
            <Text style={[styles.arrow, { color: color(tokens.textMuted) }]}>→</Text>
            <View style={styles.party}>
              <Text style={[styles.partyLabel, { color: color(tokens.textMuted) }]}>To</Text>
              <Text
                style={[styles.partyValue, { color: color(tokens.textPrimary) }]}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {receipt.recipient}
              </Text>
            </View>
          </View>
          {receipt.memo && (
            <View style={[styles.memoRow, { borderTopColor: color(tokens.border) }]}>
              <Text style={[styles.memoLabel, { color: color(tokens.textMuted) }]}>Memo</Text>
              <Text style={[styles.memoValue, { color: color(tokens.textSecondary) }]}>
                {receipt.memo}
              </Text>
            </View>
          )}
        </View>

        {/* Status Timeline */}
        <StatusTimeline events={receipt.timeline} status={receipt.status} />

        {/* Metadata Section */}
        <MetadataSection
          receiptMetadata={receipt.metadata}
          contract={receipt.contract}
          network={receipt.network}
        />

        {/* QR Code */}
        <View style={styles.qrSection}>
          <View
            style={[
              styles.qrWrapper,
              {
                backgroundColor: color(tokens.surface),
                borderColor: color(tokens.border),
                shadowColor: color(tokens.textPrimary),
              },
            ]}
          >
            <QRCode
              value={`quickex.to/receipt/${receipt.id}`}
              size={160}
              color={color(tokens.textPrimary)}
              backgroundColor={color(tokens.surface)}
            />
          </View>
          <Text style={[styles.qrLabel, { color: color(tokens.textMuted) }]}>
            Scan to verify on Stellar
          </Text>
        </View>

        {/* Action Buttons */}
        <View style={styles.actions}>
          <TouchableOpacity
            style={[styles.primaryButton, { backgroundColor: color(tokens.action.primary) }]}
            onPress={handleShare}
            activeOpacity={0.8}
          >
            <Text style={[styles.primaryButtonText, { color: color(tokens.textInverse) }]}>
              🔗 Share Receipt
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[
              styles.secondaryButton,
              {
                backgroundColor: color(tokens.surfaceElevated),
                borderColor: color(tokens.border),
              },
            ]}
            onPress={handleViewExplorer}
            activeOpacity={0.8}
          >
            <Text style={[styles.secondaryButtonText, { color: color(tokens.textPrimary) }]}>
              🔍 View on Explorer
            </Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.tertiaryButton} onPress={handleCopySupport} activeOpacity={0.8}>
            <Text style={[styles.tertiaryButtonText, { color: color(tokens.textSecondary) }]}>
              📋 Copy for Support
            </Text>
          </TouchableOpacity>
        </View>

        {/* Security Footer */}
        <View style={styles.footer}>
          <Text style={styles.footerIcon}>🔒</Text>
          <Text style={[styles.footerText, { color: color(tokens.textMuted) }]}>
            Secured by Stellar blockchain. This receipt is cryptographically verifiable.
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function themedStyles({ color, tokens, isDark }: {
  color: (t: any) => string;
  tokens: typeof themeTokens;
  isDark: boolean;
}) {
  return StyleSheet.create({
    safeArea: {
      flex: 1,
      backgroundColor: color(tokens.surface),
    },
    header: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingHorizontal: 16,
      paddingVertical: 12,
      borderBottomWidth: 1,
    },
    backButton: {
      padding: 8,
      borderRadius: 8,
    },
    backIcon: {
      fontSize: 20,
    },
    headerTitle: {
      fontSize: 18,
      fontWeight: '700',
    },
    shareButton: {
      padding: 8,
      borderRadius: 8,
    },
    shareIcon: {
      fontSize: 18,
    },
    scrollView: {
      flex: 1,
    },
    content: {
      padding: 16,
      gap: 16,
      paddingBottom: 32,
    },
    amountCard: {
      borderRadius: 20,
      padding: 24,
      borderWidth: 1,
      alignItems: 'center',
    },
    amountLabel: {
      fontSize: 14,
      textTransform: 'uppercase',
      letterSpacing: 1,
      marginBottom: 8,
    },
    amountRow: {
      flexDirection: 'row',
      alignItems: 'baseline',
      marginBottom: 20,
    },
    amountValue: {
      fontSize: 48,
      fontWeight: '800',
    },
    amountAsset: {
      fontSize: 20,
      fontWeight: '600',
      marginLeft: 8,
    },
    partiesRow: {
      flexDirection: 'row',
      alignItems: 'center',
      width: '100%',
      gap: 12,
    },
    party: {
      flex: 1,
      alignItems: 'center',
    },
    partyLabel: {
      fontSize: 11,
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      marginBottom: 4,
    },
    partyValue: {
      fontSize: 13,
      fontWeight: '600',
      fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },
    arrow: {
      fontSize: 20,
    },
    memoRow: {
      marginTop: 16,
      paddingTop: 16,
      borderTopWidth: 1,
      width: '100%',
      alignItems: 'center',
    },
    memoLabel: {
      fontSize: 11,
      marginBottom: 4,
    },
    memoValue: {
      fontSize: 14,
      fontStyle: 'italic',
    },
    qrSection: {
      alignItems: 'center',
      marginTop: 8,
    },
    qrWrapper: {
      padding: 20,
      borderRadius: 20,
      borderWidth: 2,
      shadowOffset: { width: 0, height: 2 },
      shadowOpacity: isDark ? 0.1 : 0.05,
      shadowRadius: 8,
      elevation: 2,
    },
    qrLabel: {
      marginTop: 12,
      fontSize: 13,
    },
    actions: {
      gap: 10,
      marginTop: 8,
    },
    primaryButton: {
      paddingVertical: 16,
      borderRadius: 16,
      alignItems: 'center',
      shadowColor: color(tokens.action.primary),
      shadowOffset: { width: 0, height: 4 },
      shadowOpacity: isDark ? 0.3 : 0.2,
      shadowRadius: 12,
      elevation: 4,
    },
    primaryButtonText: {
      fontSize: 16,
      fontWeight: '700',
    },
    secondaryButton: {
      paddingVertical: 16,
      borderRadius: 16,
      alignItems: 'center',
      borderWidth: 1,
    },
    secondaryButtonText: {
      fontSize: 16,
      fontWeight: '600',
    },
    tertiaryButton: {
      paddingVertical: 14,
      borderRadius: 16,
      alignItems: 'center',
    },
    tertiaryButtonText: {
      fontSize: 15,
      fontWeight: '500',
    },
    footer: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'center',
      paddingVertical: 16,
      gap: 8,
    },
    footerIcon: {
      fontSize: 14,
    },
    footerText: {
      fontSize: 12,
      textAlign: 'center',
    },
  });
}