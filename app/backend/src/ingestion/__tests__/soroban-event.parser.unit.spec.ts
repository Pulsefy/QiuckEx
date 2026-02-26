import { xdr, Address, nativeToScVal } from "stellar-sdk";
import {
  SorobanEventParser,
  RawHorizonContractEvent,
} from "../soroban-event.parser";

function symVal(s: string): xdr.ScVal {
  return xdr.ScVal.scvSymbol(s);
}

function addressVal(pubkey: string): xdr.ScVal {
  return Address.fromString(pubkey).toScVal();
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

const OWNER = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
const TOKEN = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const COMMITMENT_HEX = "deadbeef".repeat(8);

describe("SorobanEventParser", () => {
  let parser: SorobanEventParser;

  beforeEach(() => {
    parser = new SorobanEventParser();
  });

  describe("EscrowDeposited", () => {
    it("parses a valid EscrowDeposited event", () => {
      const topics = [
        symVal("EscrowDeposited"),
        bytesVal(COMMITMENT_HEX),
        addressVal(OWNER),
      ];
      const data = mapVal({
        token: addressVal(TOKEN),
        amount: nativeToScVal(5_000_000n, { type: "i128" }),
        expires_at: nativeToScVal(1800000000n, { type: "u64" }),
        timestamp: nativeToScVal(1700000000n, { type: "u64" }),
      });

      const result = parser.parse(makeRaw(topics, data));
      expect(result?.eventType).toBe("EscrowDeposited");
      if (result?.eventType !== "EscrowDeposited") return;
      expect(result.commitment).toBe(COMMITMENT_HEX);
      expect(result.owner).toBe(OWNER);
      expect(result.amount).toBe(5_000_000n);
      expect(result.expiresAt).toBe(1800000000n);
      expect(result.contractTimestamp).toBe(1700000000n);
    });
  });

  describe("EscrowWithdrawn", () => {
    it("parses a valid EscrowWithdrawn event", () => {
      const topics = [
        symVal("EscrowWithdrawn"),
        bytesVal(COMMITMENT_HEX),
        addressVal(OWNER),
      ];
      const data = mapVal({
        token: addressVal(TOKEN),
        amount: nativeToScVal(5_000_000n, { type: "i128" }),
        timestamp: nativeToScVal(1700001000n, { type: "u64" }),
      });
      const result = parser.parse(makeRaw(topics, data));
      expect(result?.eventType).toBe("EscrowWithdrawn");
    });
  });

  describe("EscrowRefunded", () => {
    it("parses a valid EscrowRefunded event", () => {
      const topics = [
        symVal("EscrowRefunded"),
        bytesVal(COMMITMENT_HEX),
        addressVal(OWNER),
      ];
      const data = mapVal({
        token: addressVal(TOKEN),
        amount: nativeToScVal(5_000_000n, { type: "i128" }),
        timestamp: nativeToScVal(1700002000n, { type: "u64" }),
      });
      const result = parser.parse(makeRaw(topics, data));
      expect(result?.eventType).toBe("EscrowRefunded");
    });
  });

  describe("PrivacyToggled", () => {
    it("parses a valid PrivacyToggled event", () => {
      const topics = [symVal("PrivacyToggled"), addressVal(OWNER)];
      const data = mapVal({
        enabled: nativeToScVal(true),
        timestamp: nativeToScVal(1700003000n, { type: "u64" }),
      });
      const result = parser.parse(makeRaw(topics, data));
      expect(result?.eventType).toBe("PrivacyToggled");
      if (result?.eventType !== "PrivacyToggled") return;
      expect(result.enabled).toBe(true);
      expect(result.owner).toBe(OWNER);
    });
  });

  describe("AdminChanged", () => {
    it("parses a valid AdminChanged event", () => {
      const ADMIN2 = "GBVVJJWOR35BPXM2XJQLMQBDNKJWKJNPGQLDNPVKPOUJDMKBDLKMNKR";
      const topics = [
        symVal("AdminChanged"),
        addressVal(OWNER),
        addressVal(ADMIN2),
      ];
      const data = mapVal({
        timestamp: nativeToScVal(1700004000n, { type: "u64" }),
      });
      const result = parser.parse(makeRaw(topics, data));
      expect(result?.eventType).toBe("AdminChanged");
      if (result?.eventType !== "AdminChanged") return;
      expect(result.oldAdmin).toBe(OWNER);
      expect(result.newAdmin).toBe(ADMIN2);
    });
  });

  describe("error cases", () => {
    it("returns null for an event with no topics", () => {
      expect(parser.parse(makeRaw([], xdr.ScVal.scvVoid()))).toBeNull();
    });

    it("returns null for an unrecognised event name", () => {
      expect(
        parser.parse(makeRaw([symVal("UnknownEvent")], xdr.ScVal.scvVoid())),
      ).toBeNull();
    });

    it("returns null and does not throw on malformed XDR", () => {
      const raw = makeRaw([], xdr.ScVal.scvVoid(), {
        topic: ["not-valid-base64!!!"],
      });
      expect(() => parser.parse(raw)).not.toThrow();
      expect(parser.parse(raw)).toBeNull();
    });
  });
});
