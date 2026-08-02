import { createHash } from "crypto";
import type { QuickExContractEvent } from "./types/contract-event.types";

/**
 * Distributive Omit — unlike the built-in Omit, this distributes over a
 * union so that `DistributiveOmit<A | B, K>` === `Omit<A, K> | Omit<B, K>`.
 * This preserves the discriminated-union structure and allows TypeScript to
 * narrow individual members inside a switch on eventType.
 */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown
  ? Omit<T, K>
  : never;

/**
 * A QuickExContractEvent with the eventId field removed.
 * This is the shape that arrives at computeEventId — eventId hasn't been
 * attached yet, which is exactly why this function exists.
 */
export type EventWithoutId = DistributiveOmit<QuickExContractEvent, "eventId">;

/**
 * Returns the ordered identity fields for a given event, matching the DB
 * UNIQUE constraints exactly:
 *   escrow_events:  UNIQUE (tx_hash, commitment, event_type)
 *   admin_events:   UNIQUE (tx_hash, event_type)
 *   privacy_events: UNIQUE (tx_hash, event_type, owner)
 *   stealth_events: UNIQUE (tx_hash, event_type, stealth_address)
 *
 * Field order is intentional — changing it would produce different hashes.
 */
function getIdentityFields(event: EventWithoutId): string[] {
  switch (event.eventType) {
    case "EscrowDeposited":
    case "EscrowWithdrawn":
    case "EscrowRefunded":
      return [event.eventType, event.txHash, event.commitment];

    case "PrivacyToggled":
      return [event.eventType, event.txHash, event.owner];

    case "ContractPaused":
      return [event.eventType, event.txHash, event.admin];

    case "AdminChanged":
      return [event.eventType, event.txHash, event.oldAdmin, event.newAdmin];

    case "ContractUpgraded":
      return [event.eventType, event.txHash, event.newWasmHash, event.admin];

    case "EphemeralKeyRegistered":
    case "StealthWithdrawn":
      return [event.eventType, event.txHash, event.stealthAddress];
  }
}

/**
 * Computes a deterministic, content-addressed identifier for a contract event.
 *
 * The same logical event always produces the same id regardless of paging
 * token or replay source, so the backend indexing can distinguish true
 * replays from genuinely new state transitions. The identity fields are
 * chosen to mirror the DB UNIQUE constraints so the new key is compatible
 * with current dedupe behaviour.
 *
 * @param event - The parsed event (without eventId, since this is called
 *   before eventId is attached).
 * @returns A 64-character lowercase hex SHA-256 digest.
 */
export function computeEventId(event: EventWithoutId): string {
  const joined = getIdentityFields(event).join("|");
  return createHash("sha256").update(joined).digest("hex");
}
