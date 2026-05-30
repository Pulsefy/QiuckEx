export const QUICKEX_EVENT_SCHEMA_VERSION = 2;

export const QUICKEX_EVENT_TOPICS = {
  admin: "TOPIC_ADMIN",
  dispute: "TOPIC_DISPUTE",
  escrow: "TOPIC_ESCROW",
  privacy: "TOPIC_PRIVACY",
  stealth: "TOPIC_STEALTH",
} as const;

export type QuickExEventTopic =
  (typeof QUICKEX_EVENT_TOPICS)[keyof typeof QUICKEX_EVENT_TOPICS];

export interface EventSchemaContract {
  topic: QuickExEventTopic;
  eventName: string;
  indexedFields: readonly string[];
  payloadKeys: readonly string[];
  schemaVersion: number;
  compatibleVersions: readonly number[];
}

export const QUICKEX_EVENT_SCHEMA_CONTRACTS = {
  EscrowDeposited: {
    topic: QUICKEX_EVENT_TOPICS.escrow,
    eventName: "EscrowDeposited",
    indexedFields: ["escrow_id", "owner"],
    payloadKeys: [
      "amount_due",
      "amount_paid",
      "expires_at",
      "schema_version",
      "timestamp",
      "token",
    ],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [1, QUICKEX_EVENT_SCHEMA_VERSION],
  },
  EscrowWithdrawn: {
    topic: QUICKEX_EVENT_TOPICS.escrow,
    eventName: "EscrowWithdrawn",
    indexedFields: ["escrow_id", "owner"],
    payloadKeys: ["amount", "fee", "schema_version", "timestamp", "token"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [1, QUICKEX_EVENT_SCHEMA_VERSION],
  },
  EscrowRefunded: {
    topic: QUICKEX_EVENT_TOPICS.escrow,
    eventName: "EscrowRefunded",
    indexedFields: ["escrow_id", "owner"],
    payloadKeys: ["amount", "schema_version", "timestamp", "token"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [1, QUICKEX_EVENT_SCHEMA_VERSION],
  },
  PrivacyToggled: {
    topic: QUICKEX_EVENT_TOPICS.privacy,
    eventName: "PrivacyToggled",
    indexedFields: ["owner"],
    payloadKeys: ["enabled", "schema_version", "timestamp"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [1, QUICKEX_EVENT_SCHEMA_VERSION],
  },
  ContractPaused: {
    topic: QUICKEX_EVENT_TOPICS.admin,
    eventName: "ContractPaused",
    indexedFields: ["admin"],
    payloadKeys: ["paused", "schema_version", "timestamp"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [QUICKEX_EVENT_SCHEMA_VERSION],
  },
  AdminChanged: {
    topic: QUICKEX_EVENT_TOPICS.admin,
    eventName: "AdminChanged",
    indexedFields: ["old_admin", "new_admin"],
    payloadKeys: ["schema_version", "timestamp"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [1, QUICKEX_EVENT_SCHEMA_VERSION],
  },
  ContractUpgraded: {
    topic: QUICKEX_EVENT_TOPICS.admin,
    eventName: "ContractUpgraded",
    indexedFields: ["new_wasm_hash", "admin"],
    payloadKeys: ["schema_version", "timestamp"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [QUICKEX_EVENT_SCHEMA_VERSION],
  },
  EphemeralKeyRegistered: {
    topic: QUICKEX_EVENT_TOPICS.stealth,
    eventName: "EphemeralKeyRegistered",
    indexedFields: ["stealth_address", "eph_pub"],
    payloadKeys: [
      "amount_due",
      "amount_paid",
      "expires_at",
      "schema_version",
      "timestamp",
      "token",
    ],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [QUICKEX_EVENT_SCHEMA_VERSION],
  },
  StealthWithdrawn: {
    topic: QUICKEX_EVENT_TOPICS.stealth,
    eventName: "StealthWithdrawn",
    indexedFields: ["stealth_address", "recipient"],
    payloadKeys: ["amount", "schema_version", "timestamp", "token"],
    schemaVersion: QUICKEX_EVENT_SCHEMA_VERSION,
    compatibleVersions: [QUICKEX_EVENT_SCHEMA_VERSION],
  },
} as const satisfies Record<string, EventSchemaContract>;

export const QUICKEX_EVENT_COMPATIBILITY = Object.fromEntries(
  Object.entries(QUICKEX_EVENT_SCHEMA_CONTRACTS).map(
    ([eventName, contract]) => [
      eventName,
      {
        currentVersion: contract.schemaVersion,
        compatibleVersions: contract.compatibleVersions,
        canonicalTopic: contract.topic,
      },
    ],
  ),
) as unknown as Record<
  keyof typeof QUICKEX_EVENT_SCHEMA_CONTRACTS,
  {
    currentVersion: number;
    compatibleVersions: readonly number[];
    canonicalTopic: QuickExEventTopic;
  }
>;
