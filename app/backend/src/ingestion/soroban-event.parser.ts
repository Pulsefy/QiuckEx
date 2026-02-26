import { Logger } from "@nestjs/common";
import { xdr, scValToNative, Address } from "stellar-sdk";

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
} from "./types/contract-event.types";

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

/**
 * Parses raw Horizon Soroban contract event records into typed domain events.
 *
 * Topic layout (per events-schema.md):
 *  Topic[0] = event name symbol
 *  Topic[1+] = indexed fields (commitment, owner, admin, etc.)
 *
 * Data = struct with remaining fields encoded as XDR ScVal.
 */
export class SorobanEventParser {
  private readonly logger = new Logger(SorobanEventParser.name);

  /**
   * Attempt to parse a raw Horizon contract event.
   * Returns null when the event is unrecognised or malformed.
   */
  parse(raw: RawHorizonContractEvent): QuickExContractEvent | null {
    try {
      const topics = raw.topic.map((t) => xdr.ScVal.fromXDR(t, "base64"));
      const dataVal = xdr.ScVal.fromXDR(raw.value.xdr, "base64");

      if (topics.length === 0) return null;

      const eventName = this.decodeSymbol(topics[0]);
      if (!eventName) return null;

      const base = {
        txHash: raw.transaction_hash,
        ledgerSequence: raw.ledger,
        pagingToken: raw.paging_token,
        contractTimestamp: this.extractTimestampFromData(dataVal),
      };

      switch (eventName as SorobanEventType) {
        case "EscrowDeposited":
          return this.parseEscrowDeposited(topics, dataVal, base);
        case "EscrowWithdrawn":
          return this.parseEscrowWithdrawn(topics, dataVal, base);
        case "EscrowRefunded":
          return this.parseEscrowRefunded(topics, dataVal, base);
        case "PrivacyToggled":
          return this.parsePrivacyToggled(topics, dataVal, base);
        case "ContractPaused":
          return this.parseContractPaused(topics, dataVal, base);
        case "AdminChanged":
          return this.parseAdminChanged(topics, dataVal, base);
        case "ContractUpgraded":
          return this.parseContractUpgraded(topics, dataVal, base);
        default:
          this.logger.debug(`Unrecognised event name: ${eventName}`);
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
      "eventType" | "commitment" | "owner" | "token" | "amount" | "expiresAt"
    >,
  ): EscrowDepositedEvent {
    // Topics: [name, commitment, owner]
    const commitment = this.decodeBytes32Hex(topics[1]);
    const owner = this.decodeAddress(topics[2]);
    const map = this.dataToMap(data);

    return {
      eventType: "EscrowDeposited",
      ...base,
      commitment,
      owner,
      token: this.decodeAddress(map["token"]),
      amount: BigInt(scValToNative(map["amount"])),
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
  ): EscrowWithdrawnEvent {
    const commitment = this.decodeBytes32Hex(topics[1]);
    const owner = this.decodeAddress(topics[2]);
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
  ): EscrowRefundedEvent {
    const commitment = this.decodeBytes32Hex(topics[1]);
    const owner = this.decodeAddress(topics[2]);
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
  ): PrivacyToggledEvent {
    const owner = this.decodeAddress(topics[1]);
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
  ): ContractPausedEvent {
    const admin = this.decodeAddress(topics[1]);
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
  ): AdminChangedEvent {
    const oldAdmin = this.decodeAddress(topics[1]);
    const newAdmin = this.decodeAddress(topics[2]);

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
  ): ContractUpgradedEvent {
    const newWasmHash = this.decodeBytes32Hex(topics[1]);
    const admin = this.decodeAddress(topics[2]);

    return {
      eventType: "ContractUpgraded",
      ...base,
      newWasmHash,
      admin,
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
}
