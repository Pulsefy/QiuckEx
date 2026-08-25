export type PrivacySubjectKey = 'publicKey' | 'username' | 'userId';

export type RetentionAction = 'delete' | 'anonymize';

export type RetentionCutoffMode = 'age' | 'absolute';

export interface SubjectIdentifier {
  key: PrivacySubjectKey;
  column: string;
}

export interface RetentionPolicy {
  storeKey: string;
  tableName: string;
  description: string;
  retentionDays: number;
  retentionColumn: string;
  cutoffMode: RetentionCutoffMode;
  action: RetentionAction;
  subjectIdentifiers: SubjectIdentifier[];
  anonymizeColumns?: string[];
  nullColumns?: string[];
  setColumns?: Record<string, unknown>;
  financialIntegrityNote?: string;
}

const SEVEN_YEARS_DAYS = 2555;

/**
 * Central declaration for personal-data stores handled by retention and
 * right-to-erasure workflows.
 */
export const DATA_RETENTION_POLICIES: readonly RetentionPolicy[] = [
  {
    storeKey: 'public_profiles',
    tableName: 'usernames',
    description: 'Public username/profile ownership records.',
    retentionDays: 3650,
    retentionColumn: 'created_at',
    cutoffMode: 'age',
    action: 'delete',
    subjectIdentifiers: [
      { key: 'publicKey', column: 'public_key' },
      { key: 'username', column: 'username' },
    ],
  },
  {
    storeKey: 'crash_reports',
    tableName: 'crash_reports',
    description: 'Opt-in crash reports, issue reports, and redacted logs.',
    retentionDays: 30,
    retentionColumn: 'timestamp',
    cutoffMode: 'age',
    action: 'delete',
    subjectIdentifiers: [{ key: 'userId', column: 'user_id' }],
  },
  {
    storeKey: 'crash_reporting_settings',
    tableName: 'crash_reporting_settings',
    description: 'Per-user crash-reporting opt-in settings.',
    retentionDays: 365,
    retentionColumn: 'updated_at',
    cutoffMode: 'age',
    action: 'delete',
    subjectIdentifiers: [{ key: 'userId', column: 'user_id' }],
  },
  {
    storeKey: 'notification_preferences',
    tableName: 'notification_preferences',
    description: 'Notification destinations and user channel preferences.',
    retentionDays: 365,
    retentionColumn: 'updated_at',
    cutoffMode: 'age',
    action: 'delete',
    subjectIdentifiers: [{ key: 'publicKey', column: 'public_key' }],
  },
  {
    storeKey: 'notification_log',
    tableName: 'notification_log',
    description: 'Notification delivery attempts and retry diagnostics.',
    retentionDays: 180,
    retentionColumn: 'created_at',
    cutoffMode: 'age',
    action: 'delete',
    subjectIdentifiers: [{ key: 'publicKey', column: 'public_key' }],
  },
  {
    storeKey: 'abuse_signals',
    tableName: 'abuse_signals',
    description: 'Privacy-safe abuse signals for public payment endpoints.',
    retentionDays: 90,
    retentionColumn: 'retention_until',
    cutoffMode: 'absolute',
    action: 'delete',
    subjectIdentifiers: [{ key: 'username', column: 'target_username' }],
  },
  {
    storeKey: 'support_bundle_references',
    tableName: 'support_bundle_references',
    description: 'Support bundle pointers and ticket/receipt links.',
    retentionDays: 30,
    retentionColumn: 'expires_at',
    cutoffMode: 'absolute',
    action: 'anonymize',
    subjectIdentifiers: [
      { key: 'userId', column: 'created_by' },
      { key: 'publicKey', column: 'created_by' },
    ],
    anonymizeColumns: ['bundle_id', 'created_by'],
    setColumns: { redacted: true },
    financialIntegrityNote:
      'Support bundle references are redacted instead of deleted so support audit history can explain why a ticket lost its bundle pointer.',
  },
  {
    storeKey: 'payment_links',
    tableName: 'payment_links',
    description: 'Payment link records that may be referenced by reconciliation and receipts.',
    retentionDays: SEVEN_YEARS_DAYS,
    retentionColumn: 'created_at',
    cutoffMode: 'age',
    action: 'anonymize',
    subjectIdentifiers: [
      { key: 'publicKey', column: 'owner_public_key' },
      { key: 'publicKey', column: 'destination_public_key' },
    ],
    anonymizeColumns: ['owner_public_key', 'destination_public_key'],
    nullColumns: ['memo', 'reference_id'],
    financialIntegrityNote:
      'Payment links are anonymized rather than deleted because matched links can be needed to reconcile on-chain financial activity.',
  },
  {
    storeKey: 'recurring_payment_links',
    tableName: 'recurring_payment_links',
    description: 'Recurring payment schedules and execution source metadata.',
    retentionDays: SEVEN_YEARS_DAYS,
    retentionColumn: 'created_at',
    cutoffMode: 'age',
    action: 'anonymize',
    subjectIdentifiers: [
      { key: 'publicKey', column: 'destination' },
      { key: 'username', column: 'username' },
    ],
    anonymizeColumns: ['destination', 'username'],
    nullColumns: ['memo', 'reference_id'],
    financialIntegrityNote:
      'Recurring payment links keep schedule and amount history for financial integrity, but user identifiers are anonymized.',
  },
  {
    storeKey: 'unmatched_transactions',
    tableName: 'unmatched_transactions',
    description: 'Unmatched transaction review queue for financial reconciliation.',
    retentionDays: SEVEN_YEARS_DAYS,
    retentionColumn: 'ingested_at',
    cutoffMode: 'age',
    action: 'anonymize',
    subjectIdentifiers: [
      { key: 'publicKey', column: 'source_account' },
      { key: 'publicKey', column: 'destination_account' },
      { key: 'userId', column: 'resolved_by' },
    ],
    anonymizeColumns: ['source_account', 'destination_account', 'resolved_by'],
    nullColumns: ['memo', 'resolution_note'],
    financialIntegrityNote:
      'Unmatched transaction rows preserve transaction hashes and amounts for reconciliation, while account identifiers are anonymized.',
  },
  {
    storeKey: 'admin_audit_logs',
    tableName: 'admin_audit_logs',
    description: 'Administrative audit trail.',
    retentionDays: SEVEN_YEARS_DAYS,
    retentionColumn: 'created_at',
    cutoffMode: 'age',
    action: 'anonymize',
    subjectIdentifiers: [
      { key: 'userId', column: 'actor' },
      { key: 'publicKey', column: 'actor' },
      { key: 'userId', column: 'target' },
      { key: 'publicKey', column: 'target' },
    ],
    anonymizeColumns: ['actor', 'target'],
    setColumns: { metadata: {} },
    financialIntegrityNote:
      'Audit rows are anonymized rather than deleted so administrative and security investigations retain a durable event trail.',
  },
];

