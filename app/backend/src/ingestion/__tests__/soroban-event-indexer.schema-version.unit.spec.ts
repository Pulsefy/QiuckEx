import { xdr, nativeToScVal } from "@stellar/stellar-sdk";
import {
  SorobanEventParser,
  RawHorizonContractEvent,
  MAX_SUPPORTED_SCHEMA_VERSION,
  UnknownSchemaVersionHandler,
} from "../soroban-event.parser";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function symVal(s: string): xdr.ScVal {
  return xdr.ScVal.scvSymbol(s);
}

function addressVal(pubkey: string): xdr.ScVal {
  return nativeToScVal(pubkey);
}

function bytesVal(hex: string): xdr.ScVal {
  return xdr.ScVal.scvBytes(Buffer.from(hex, "hex"));
}

function mapVal(entries: Record<string, xdr.ScVal>): xdr.ScVal {
  const mapEntries = Object.entries(entries).map(
    ([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v }),
  );
  return xdr.ScVal.scvMap(mapEntries);
}

function makeRaw(
  topics: xdr.ScVal[],
  data: xdr.ScVal,
  overrides: Partial<RawHorizonContractEvent> = {},
): RawHorizonContractEvent {
  return {
    id: "1",
    paging_token: "100-1",
    transaction_hash: "txhash1",
    ledger: 100,
    created_at: "2025-01-01T00:00:00Z",
    contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    type: "contract",
    topic: topics.map((v) => v.toXDR("base64")),
    value: { xdr: data.toXDR("base64") },
    ...overrides,
  };
}

const OWNER = "GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2";
const TOKEN = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const COMMITMENT_HEX = "deadbeef".repeat(8);

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("SorobanEventParser – schema version handling", () => {
  it("treats absent schema_version as v1", () => {
    const parser = new SorobanEventParser();
    const topics = [symVal("EscrowDeposited"), bytesVal(COMMITMENT_HEX), addressVal(OWNER)];
    const data = mapVal({
      token: addressVal(TOKEN),
      amount: nativeToScVal(1_000n, { type: "i128" }),
      expires_at: nativeToScVal(9999999n, { type: "u64" }),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
      // no schema_version key
    });

    const result = parser.parse(makeRaw(topics, data));
    expect(result).not.toBeNull();
    expect(result!.schemaVersion).toBe(1);
  });

  it("accepts schema_version == 2", () => {
    const parser = new SorobanEventParser();
    const topics = [symVal("EscrowDeposited"), bytesVal(COMMITMENT_HEX), addressVal(OWNER)];
    const data = mapVal({
      schema_version: nativeToScVal(2, { type: "u32" }),
      token: addressVal(TOKEN),
      amount: nativeToScVal(1_000n, { type: "i128" }),
      expires_at: nativeToScVal(9999999n, { type: "u64" }),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
    });

    const result = parser.parse(makeRaw(topics, data));
    expect(result).not.toBeNull();
    expect(result!.schemaVersion).toBe(2);
  });

  it("rejects schema_version > MAX_SUPPORTED and calls the handler", () => {
    const handler: UnknownSchemaVersionHandler = jest.fn();
    const parser = new SorobanEventParser(handler);

    const unknownVersion = MAX_SUPPORTED_SCHEMA_VERSION + 1;
    const topics = [symVal("EscrowDeposited"), bytesVal(COMMITMENT_HEX), addressVal(OWNER)];
    const data = mapVal({
      schema_version: nativeToScVal(unknownVersion, { type: "u32" }),
      token: addressVal(TOKEN),
      amount: nativeToScVal(1_000n, { type: "i128" }),
      expires_at: nativeToScVal(9999999n, { type: "u64" }),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
    });

    const result = parser.parse(makeRaw(topics, data, { paging_token: "999-1" }));
    expect(result).toBeNull();
    expect(handler).toHaveBeenCalledWith("EscrowDeposited", unknownVersion, "999-1");
  });

  it("does not call the handler for supported versions", () => {
    const handler: UnknownSchemaVersionHandler = jest.fn();
    const parser = new SorobanEventParser(handler);

    const topics = [symVal("PrivacyToggled"), addressVal(OWNER)];
    const data = mapVal({
      schema_version: nativeToScVal(2, { type: "u32" }),
      enabled: nativeToScVal(true),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
    });

    parser.parse(makeRaw(topics, data));
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("SorobanEventParser – PrivacyToggled", () => {
  it("parses PrivacyToggled with schema_version=2", () => {
    const parser = new SorobanEventParser();
    const topics = [symVal("PrivacyToggled"), addressVal(OWNER)];
    const data = mapVal({
      schema_version: nativeToScVal(2, { type: "u32" }),
      enabled: nativeToScVal(false),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
    });

    const result = parser.parse(makeRaw(topics, data));
    expect(result?.eventType).toBe("PrivacyToggled");
    if (result?.eventType !== "PrivacyToggled") return;
    expect(result.owner).toBe(OWNER);
    expect(result.enabled).toBe(false);
    expect(result.schemaVersion).toBe(2);
  });
});

describe("SorobanEventParser – EphemeralKeyRegistered", () => {
  const STEALTH_HEX = "cafebabe".repeat(8);
  const EPH_PUB_HEX = "deadcafe".repeat(8);

  it("parses EphemeralKeyRegistered", () => {
    const parser = new SorobanEventParser();
    const topics = [
      symVal("EphemeralKeyRegistered"),
      bytesVal(STEALTH_HEX),
      bytesVal(EPH_PUB_HEX),
    ];
    const data = mapVal({
      schema_version: nativeToScVal(2, { type: "u32" }),
      token: addressVal(TOKEN),
      amount: nativeToScVal(500n, { type: "i128" }),
      expires_at: nativeToScVal(9999999n, { type: "u64" }),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
    });

    const result = parser.parse(makeRaw(topics, data));
    expect(result?.eventType).toBe("EphemeralKeyRegistered");
    if (result?.eventType !== "EphemeralKeyRegistered") return;
    expect(result.stealthAddress).toBe(STEALTH_HEX);
    expect(result.ephPub).toBe(EPH_PUB_HEX);
    expect(result.amount).toBe(500n);
  });
});
