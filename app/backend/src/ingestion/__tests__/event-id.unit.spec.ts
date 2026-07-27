import { computeEventId, type EventWithoutId } from "../event-id";

// ── Shared test fixtures ─────────────────────────────────────────────────────

const TX_HASH = "aabbccdd".repeat(8);
const TX_HASH_2 = "11223344".repeat(8);
const COMMITMENT = "deadbeef".repeat(8);
const COMMITMENT_2 = "cafebabe".repeat(8);
const OWNER = "GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2";
const ADMIN = "GB7QNDHSBQZENWGZUBJ4KLSZFRNHN5ATQXZSC3ZHZ5ZBQ6Y6X3TOBQ7S";
const ADMIN_2 = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGQKPFPXYKD5E2HPUCD7VM";
const STEALTH = "facade00".repeat(8);
const WASM_HASH = "baadf00d".repeat(8);
const TOKEN = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/** Minimal base fields shared by all event fixtures. */
const BASE = {
  schemaVersion: 2,
  txHash: TX_HASH,
  ledgerSequence: 100,
  pagingToken: "100-1",
  contractTimestamp: 1700000000n,
} as const;

// ── One fixture per event type (without eventId) ────────────────────────────
// EventWithoutId is a distributive Omit so each member keeps its specific fields.

const FIXTURES: EventWithoutId[] = [
  {
    ...BASE,
    eventType: "EscrowDeposited",
    commitment: COMMITMENT,
    owner: OWNER,
    token: TOKEN,
    amount: 5_000_000n,
    amountPaid: 5_000_000n,
    expiresAt: 1800000000n,
  },
  {
    ...BASE,
    eventType: "EscrowWithdrawn",
    commitment: COMMITMENT,
    owner: OWNER,
    token: TOKEN,
    amount: 5_000_000n,
  },
  {
    ...BASE,
    eventType: "EscrowRefunded",
    commitment: COMMITMENT,
    owner: OWNER,
    token: TOKEN,
    amount: 5_000_000n,
  },
  {
    ...BASE,
    eventType: "PrivacyToggled",
    owner: OWNER,
    enabled: true,
  },
  {
    ...BASE,
    eventType: "ContractPaused",
    admin: ADMIN,
    paused: true,
  },
  {
    ...BASE,
    eventType: "AdminChanged",
    oldAdmin: ADMIN,
    newAdmin: ADMIN_2,
  },
  {
    ...BASE,
    eventType: "ContractUpgraded",
    newWasmHash: WASM_HASH,
    admin: ADMIN,
  },
  {
    ...BASE,
    eventType: "EphemeralKeyRegistered",
    stealthAddress: STEALTH,
    ephPub: WASM_HASH,
    token: TOKEN,
    amount: 1_000_000n,
    expiresAt: 1900000000n,
  },
  {
    ...BASE,
    eventType: "StealthWithdrawn",
    stealthAddress: STEALTH,
    recipient: OWNER,
    token: TOKEN,
    amount: 1_000_000n,
  },
];

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

// ── Tests ────────────────────────────────────────────────────────────────────

describe("computeEventId", () => {
  it("(a) returns the same id for two calls with identical event objects", () => {
    const event = FIXTURES[0]; // EscrowDeposited
    expect(computeEventId(event)).toBe(computeEventId(event));
  });

  it("(b) two EscrowDeposited events with different commitments produce different ids", () => {
    const e1: EventWithoutId = {
      ...BASE,
      eventType: "EscrowDeposited",
      commitment: COMMITMENT,
      owner: OWNER,
      token: TOKEN,
      amount: 5_000_000n,
      amountPaid: 5_000_000n,
      expiresAt: 1800000000n,
    };
    const e2: EventWithoutId = {
      ...BASE,
      eventType: "EscrowDeposited",
      commitment: COMMITMENT_2,
      owner: OWNER,
      token: TOKEN,
      amount: 5_000_000n,
      amountPaid: 5_000_000n,
      expiresAt: 1800000000n,
    };
    expect(computeEventId(e1)).not.toBe(computeEventId(e2));
  });

  it("(c) two EscrowDeposited events with same commitment but different txHash produce different ids", () => {
    const e1: EventWithoutId = {
      ...BASE,
      eventType: "EscrowDeposited",
      commitment: COMMITMENT,
      owner: OWNER,
      token: TOKEN,
      amount: 5_000_000n,
      amountPaid: 5_000_000n,
      expiresAt: 1800000000n,
    };
    const e2: EventWithoutId = {
      ...BASE,
      txHash: TX_HASH_2,
      eventType: "EscrowDeposited",
      commitment: COMMITMENT,
      owner: OWNER,
      token: TOKEN,
      amount: 5_000_000n,
      amountPaid: 5_000_000n,
      expiresAt: 1800000000n,
    };
    expect(computeEventId(e1)).not.toBe(computeEventId(e2));
  });

  it("(d) each of the 9 event types produces a non-empty, deterministic 64-character hex string", () => {
    expect(FIXTURES).toHaveLength(9);
    for (const event of FIXTURES) {
      const id1 = computeEventId(event);
      const id2 = computeEventId(event);
      expect(id1).toMatch(SHA256_HEX_RE);
      expect(id1.length).toBe(64);
      expect(id1).toBe(id2);
    }
  });

  it("(e) AdminChanged events with swapped oldAdmin/newAdmin produce different ids (order matters)", () => {
    const forward: EventWithoutId = {
      ...BASE,
      eventType: "AdminChanged",
      oldAdmin: ADMIN,
      newAdmin: ADMIN_2,
    };
    const swapped: EventWithoutId = {
      ...BASE,
      eventType: "AdminChanged",
      oldAdmin: ADMIN_2,
      newAdmin: ADMIN,
    };
    expect(computeEventId(forward)).not.toBe(computeEventId(swapped));
  });
});
