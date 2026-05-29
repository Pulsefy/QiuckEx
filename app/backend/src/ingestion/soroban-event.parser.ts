import { Logger } from "@nestjs/common";
import { xdr, scValToNative, Address } from "@stellar/stellar-sdk";

import type {
  QuickExContractEvent,
  SorobanEventType,
  EscrowDepositedEvent,
  EscrowWithdrawnEvent,
  EscrowRefundedEvent,
  PrivacyToggledEvent,
  ContractPausedEvent,
  AdminChangedEvent,
  ContractUpgradedEvent,
  EphemeralKeyRegisteredEvent,
  StealthWithdrawnEvent,
} from "./types/contract-event.types";
import {
  QUICKEX_EVENT_SCHEMA_CONTRACTS,
  QUICKEX_EVENT_TOPICS,
  type QuickExEventTopic,
} from "./event-schema";

/** Maximum schema version this indexer understands. */
export const MAX_SUPPORTED_SCHEMA_VERSION = 2;

/**
 * Raw Horizon contract event record shape (subset we need).
 */
export interface RawHorizonContractEvent {
  id: string;
  paging_token: string;
  transaction_hash: string;
  ledger: number;
  created_at: string; // ISO date string from Horizon
  contract_id: string;
  type: string;
  topic: string[]; // base64-encoded XDR ScVal strings
  value: { xdr: string }; // base64-encoded XDR ScVal
}

interface TopicLayout {
  eventName: SorobanEventType;
  topicNamespace: QuickExEventTopic | "LEGACY";
  indexedOffset: number;
}

/**
 * Parses raw Horizon Soroban contract event records into typed domain events.
 *
 * Canonical topic layout:
 *  Topic[0] = stable QuickEx testnet namespace (for example TOPIC_ESCROW)
 *  Topic[1] = event name symbol
 *  Topic[2+] = indexed fields (commitment, owner, admin, etc.)
 *
 * Data = struct with remaining fields encoded as XDR ScVal.
 *
 * Legacy events used Topic[0] = event name. The parser keeps a compatibility
 * path for those events and marks them with schemaVersion=1.
 */
export class SorobanEventParser {
  private readonly logger = new Logger(SorobanEventParser.name);

  constructor(
    private readonly onUnknownSchemaVersion?: UnknownSchemaVersionHandler,
  ) {}

  /**
   * Attempt to parse a raw Horizon contract event.
   * Returns null when the event is unrecognised, malformed, or carries an
   * unsupported schema version.
   */
  parse(raw: RawHorizonContractEvent): QuickExContractEvent | null {
    try {
      const topics = raw.topic.map((t) => xdr.ScVal.fromXDR(t, "base64"));
      const dataVal = xdr.ScVal.fromXDR(raw.value.xdr, "base64");

      if (topics.length === 0) return null;

      const layout = this.resolveTopicLayout(topics);
      if (!layout) return null;

      const schemaVersion = this.extractSchemaVersionFromData(dataVal);
      if (!this.isCompatibleSchemaVersion(layout.eventName, schemaVersion)) {
        this.logger.warn(
          `Unsupported ${layout.eventName} schema version ${schemaVersion}`,
        );
        return null;
      }

      // ── Schema version gate ──────────────────────────────────────────────
      const schemaVersion = this.extractSchemaVersion(dataVal);
      if (schemaVersion > MAX_SUPPORTED_SCHEMA_VERSION) {
        this.logger.warn(
          `Skipping event ${eventName} paging_token=${raw.paging_token}: ` +
            `schema_version=${schemaVersion} exceeds max supported (${MAX_SUPPORTED_SCHEMA_VERSION})`,
        );
        this.onUnknownSchemaVersion?.(eventName, schemaVersion, raw.paging_token);
        return null;
      }

      const base = {
        schemaVersion,
        topicNamespace: layout.topicNamespace,
        txHash: raw.transaction_hash,
        ledgerSequence: raw.ledger,
        pagingToken: raw.paging_token,
        contractTimestamp: this.extractTimestampFromData(dataVal),
        schemaVersion,
      };

      switch (layout.eventName) {
        case "EscrowDeposited":
          return this.parseEscrowDeposited(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "EscrowWithdrawn":
          return this.parseEscrowWithdrawn(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "EscrowRefunded":
          return this.parseEscrowRefunded(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "PrivacyToggled":
          return this.parsePrivacyToggled(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "ContractPaused":
          return this.parseContractPaused(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "AdminChanged":
          return this.parseAdminChanged(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "ContractUpgraded":
          return this.parseContractUpgraded(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "EphemeralKeyRegistered":
          return this.parseEphemeralKeyRegistered(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        case "StealthWithdrawn":
          return this.parseStealthWithdrawn(
            topics,
            dataVal,
            base,
            layout.indexedOffset,
          );
        default:
          this.logger.debug(`Unrecognised event name: ${layout.eventName}`);
          return null;
      }
    } catch (err) {
      this.logger.warn(
        `Failed to parse contract event ${raw.paging_token}: ${(err as Error).message}`,
      );
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Escrow event parsers
  // ---------------------------------------------------------------------------

  private parseEscrowDeposited(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<
      EscrowDepositedEvent,
      | "eventType"
      | "commitment"
      | "owner"
      | "token"
      | "amount"
      | "amountPaid"
      | "expiresAt"
    >,
    indexedOffset: number,
  ): EscrowDepositedEvent {
    const commitment = this.decodeBytes32Hex(topics[indexedOffset]);
    const owner = this.decodeAddress(topics[indexedOffset + 1]);
    const map = this.dataToMap(data);

    return {
      eventType: "EscrowDeposited",
      ...base,
      commitment,
      owner,
      token: this.decodeAddress(map["token"]),
      amount: BigInt(scValToNative(map["amount_due"] ?? map["amount"])),
      amountPaid: BigInt(scValToNative(map["amount_paid"] ?? map["amount"])),
      expiresAt: BigInt(scValToNative(map["expires_at"])),
    };
  }

  private parseEscrowWithdrawn(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<
      EscrowWithdrawnEvent,
      "eventType" | "commitment" | "owner" | "token" | "amount"
    >,
    indexedOffset: number,
  ): EscrowWithdrawnEvent {
    const commitment = this.decodeBytes32Hex(topics[indexedOffset]);
    const owner = this.decodeAddress(topics[indexedOffset + 1]);
    const map = this.dataToMap(data);

    return {
      eventType: "EscrowWithdrawn",
      ...base,
      commitment,
      owner,
      token: this.decodeAddress(map["token"]),
      amount: BigInt(scValToNative(map["amount"])),
    };
  }

  private parseEscrowRefunded(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<
      EscrowRefundedEvent,
      "eventType" | "commitment" | "owner" | "token" | "amount"
    >,
    indexedOffset: number,
  ): EscrowRefundedEvent {
    const commitment = this.decodeBytes32Hex(topics[indexedOffset]);
    const owner = this.decodeAddress(topics[indexedOffset + 1]);
    const map = this.dataToMap(data);

    return {
      eventType: "EscrowRefunded",
      ...base,
      commitment,
      owner,
      token: this.decodeAddress(map["token"]),
      amount: BigInt(scValToNative(map["amount"])),
    };
  }

  // ---------------------------------------------------------------------------
  // Admin / Privacy event parsers
  // ---------------------------------------------------------------------------

  private parsePrivacyToggled(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<PrivacyToggledEvent, "eventType" | "owner" | "enabled">,
    indexedOffset: number,
  ): PrivacyToggledEvent {
    const owner = this.decodeAddress(topics[indexedOffset]);
    const map = this.dataToMap(data);

    return {
      eventType: "PrivacyToggled",
      ...base,
      owner,
      enabled: Boolean(scValToNative(map["enabled"])),
    };
  }

  private parseContractPaused(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<ContractPausedEvent, "eventType" | "admin" | "paused">,
    indexedOffset: number,
  ): ContractPausedEvent {
    const admin = this.decodeAddress(topics[indexedOffset]);
    const map = this.dataToMap(data);

    return {
      eventType: "ContractPaused",
      ...base,
      admin,
      paused: Boolean(scValToNative(map["paused"])),
    };
  }

  private parseAdminChanged(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<AdminChangedEvent, "eventType" | "oldAdmin" | "newAdmin">,
    indexedOffset: number,
  ): AdminChangedEvent {
    const oldAdmin = this.decodeAddress(topics[indexedOffset]);
    const newAdmin = this.decodeAddress(topics[indexedOffset + 1]);

    return {
      eventType: "AdminChanged",
      ...base,
      oldAdmin,
      newAdmin,
    };
  }

  private parseContractUpgraded(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<ContractUpgradedEvent, "eventType" | "newWasmHash" | "admin">,
    indexedOffset: number,
  ): ContractUpgradedEvent {
    const newWasmHash = this.decodeBytes32Hex(topics[indexedOffset]);
    const admin = this.decodeAddress(topics[indexedOffset + 1]);

    return {
      eventType: "ContractUpgraded",
      ...base,
      newWasmHash,
      admin,
    };
  }

  // ---------------------------------------------------------------------------
  // Stealth address event parsers (Privacy v2 – Issue #157)
  // ---------------------------------------------------------------------------

  private parseEphemeralKeyRegistered(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<
      EphemeralKeyRegisteredEvent,
      | "eventType"
      | "stealthAddress"
      | "ephPub"
      | "token"
      | "amount"
      | "expiresAt"
    >,
    indexedOffset: number,
  ): EphemeralKeyRegisteredEvent {
    const stealthAddress = this.decodeBytes32Hex(topics[indexedOffset]);
    const ephPub = this.decodeBytes32Hex(topics[indexedOffset + 1]);
    const map = this.dataToMap(data);

    return {
      eventType: "EphemeralKeyRegistered",
      ...base,
      stealthAddress,
      ephPub,
      token: this.decodeAddress(map["token"]),
      amount: BigInt(scValToNative(map["amount_due"] ?? map["amount"])),
      expiresAt: BigInt(scValToNative(map["expires_at"])),
    };
  }

  private parseStealthWithdrawn(
    topics: xdr.ScVal[],
    data: xdr.ScVal,
    base: Omit<
      StealthWithdrawnEvent,
      "eventType" | "stealthAddress" | "recipient" | "token" | "amount"
    >,
    indexedOffset: number,
  ): StealthWithdrawnEvent {
    const stealthAddress = this.decodeBytes32Hex(topics[indexedOffset]);
    const recipient = this.decodeAddress(topics[indexedOffset + 1]);
    const map = this.dataToMap(data);

    return {
      eventType: "StealthWithdrawn",
      ...base,
      stealthAddress,
      recipient,
      token: this.decodeAddress(map["token"]),
      amount: BigInt(scValToNative(map["amount"])),
    };
  }

  // ---------------------------------------------------------------------------
  // XDR decode helpers
  // ---------------------------------------------------------------------------

  private decodeSymbol(val: xdr.ScVal): string | null {
    try {
      return val.sym().toString();
    } catch {
      return null;
    }
  }

  private resolveTopicLayout(topics: xdr.ScVal[]): TopicLayout | null {
    const first = this.decodeSymbol(topics[0]);
    if (!first) return null;

    const canonicalTopics = new Set<string>(
      Object.values(QUICKEX_EVENT_TOPICS),
    );
    if (canonicalTopics.has(first)) {
      const second = topics[1] ? this.decodeSymbol(topics[1]) : null;
      if (!second || !(second in QUICKEX_EVENT_SCHEMA_CONTRACTS)) return null;

      const contract =
        QUICKEX_EVENT_SCHEMA_CONTRACTS[
          second as keyof typeof QUICKEX_EVENT_SCHEMA_CONTRACTS
        ];
      if (contract.topic !== first) return null;

      return {
        eventName: second as SorobanEventType,
        topicNamespace: first as QuickExEventTopic,
        indexedOffset: 2,
      };
    }

    if (first in QUICKEX_EVENT_SCHEMA_CONTRACTS) {
      return {
        eventName: first as SorobanEventType,
        topicNamespace: "LEGACY",
        indexedOffset: 1,
      };
    }

    return null;
  }

  private isCompatibleSchemaVersion(
    eventName: SorobanEventType,
    schemaVersion: number,
  ): boolean {
    const contract =
      QUICKEX_EVENT_SCHEMA_CONTRACTS[
        eventName as keyof typeof QUICKEX_EVENT_SCHEMA_CONTRACTS
      ];

    return (contract.compatibleVersions as readonly number[]).includes(
      schemaVersion,
    );
  }

  private decodeAddress(val: xdr.ScVal): string {
    const native = scValToNative(val);
    if (typeof native === "string") return native;
    // It may already be an Address object
    return Address.fromScVal(val).toString();
  }

  private decodeBytes32Hex(val: xdr.ScVal): string {
    const bytes: Buffer = scValToNative(val);
    return bytes.toString("hex");
  }

  /**
   * Converts a Soroban map ScVal into a plain JS Record keyed by field name.
   */
  private dataToMap(data: xdr.ScVal): Record<string, xdr.ScVal> {
    const result: Record<string, xdr.ScVal> = {};
    const mapEntries = data.map();

    for (const entry of mapEntries) {
      const key = entry.key().sym().toString();
      result[key] = entry.val();
    }

    return result;
  }

  private extractSchemaVersionFromData(data: xdr.ScVal): number {
    try {
      const map = this.dataToMap(data);
      if (map["schema_version"]) {
        return Number(scValToNative(map["schema_version"]));
      }
    } catch {
      // Legacy events did not include schema_version.
    }
    return 1;
  }

  private extractTimestampFromData(data: xdr.ScVal): bigint {
    try {
      const map = this.dataToMap(data);
      if (map["timestamp"]) {
        return BigInt(scValToNative(map["timestamp"]));
      }
    } catch {
      // ignore
    }
    return 0n;
  }

  /**
   * Reads `schema_version` from the data map.
   * - Absent → v1 (legacy events without the field).
   * - Present → the numeric value.
   */
  private extractSchemaVersion(data: xdr.ScVal): number {
    try {
      const map = this.dataToMap(data);
      if (map["schema_version"]) {
        return Number(scValToNative(map["schema_version"]));
      }
    } catch {
      // ignore
    }
    return 1; // v1: no schema_version field
  }
}
