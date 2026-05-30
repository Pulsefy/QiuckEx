import { EventEmitter2 } from "@nestjs/event-emitter";
import { xdr, nativeToScVal } from "@stellar/stellar-sdk";

import { SorobanEventIndexerService } from "../soroban-event-indexer.service";
import { RawHorizonContractEvent } from "../soroban-event.parser";
import { IndexerCheckpointRepository } from "../indexer-checkpoint.repository";
import { EscrowEventRepository } from "../escrow-event.repository";
import { PrivacyEventRepository } from "../privacy-event.repository";
import { AdminEventRepository } from "../admin-event.repository";
import { StealthEventRepository } from "../stealth-event.repository";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function symVal(s: string) { return xdr.ScVal.scvSymbol(s); }
function addressVal(s: string) { return nativeToScVal(s); }
function bytesVal(hex: string) { return xdr.ScVal.scvBytes(Buffer.from(hex, "hex")); }
function mapVal(entries: Record<string, xdr.ScVal>) {
  return xdr.ScVal.scvMap(
    Object.entries(entries).map(
      ([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v }),
    ),
  );
}

const OWNER = "GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2";
const TOKEN = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const COMMITMENT_HEX = "deadbeef".repeat(8);
const CONTRACT_ID = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

function makeEscrowDepositedRaw(ledger: number, pagingToken: string): RawHorizonContractEvent {
  const topics = [symVal("EscrowDeposited"), bytesVal(COMMITMENT_HEX), addressVal(OWNER)];
  const data = mapVal({
    schema_version: nativeToScVal(2, { type: "u32" }),
    token: addressVal(TOKEN),
    amount: nativeToScVal(1_000n, { type: "i128" }),
    expires_at: nativeToScVal(9999999n, { type: "u64" }),
    timestamp: nativeToScVal(1700000000n, { type: "u64" }),
  });
  return {
    id: pagingToken,
    paging_token: pagingToken,
    transaction_hash: `tx-${pagingToken}`,
    ledger,
    created_at: "2026-01-01T00:00:00Z",
    contract_id: CONTRACT_ID,
    type: "contract",
    topic: topics.map((v) => v.toXDR("base64")),
    value: { xdr: data.toXDR("base64") },
  };
}

// ─── Mocks ───────────────────────────────────────────────────────────────────

function buildMocks() {
  const config = { network: "testnet" } as never;

  const checkpointRepo = {
    getLastLedger: jest.fn().mockResolvedValue(null),
    saveLastLedger: jest.fn().mockResolvedValue(undefined),
  } as unknown as IndexerCheckpointRepository;

  const escrowRepo = {
    upsertEvent: jest.fn().mockResolvedValue(undefined),
  } as unknown as EscrowEventRepository;

  const privacyRepo = {
    upsertEvent: jest.fn().mockResolvedValue(undefined),
  } as unknown as PrivacyEventRepository;

  const adminRepo = {
    upsertEvent: jest.fn().mockResolvedValue(undefined),
  } as unknown as AdminEventRepository;

  const stealthRepo = {
    upsertEvent: jest.fn().mockResolvedValue(undefined),
  } as unknown as StealthEventRepository;

  const metrics = {
    recordUnknownSchemaVersion: jest.fn(),
  } as never;

  const eventEmitter = { emit: jest.fn() } as unknown as EventEmitter2;

  return { config, checkpointRepo, escrowRepo, privacyRepo, adminRepo, stealthRepo, metrics, eventEmitter };
}

function buildService(mocks: ReturnType<typeof buildMocks>) {
  return new SorobanEventIndexerService(
    mocks.config,
    mocks.checkpointRepo,
    mocks.escrowRepo,
    mocks.privacyRepo,
    mocks.adminRepo,
    mocks.stealthRepo,
    mocks.metrics,
    mocks.eventEmitter,
  );
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("SorobanEventIndexerService", () => {
  let fetchSpy: jest.SpyInstance;

  afterEach(() => {
    fetchSpy?.mockRestore();
  });

  function mockHorizonPage(records: RawHorizonContractEvent[]) {
    fetchSpy = jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({
        _embedded: { records },
        _links: {},
      }),
    } as Response);
  }

  it("persists events and advances checkpoint", async () => {
    const mocks = buildMocks();
    const svc = buildService(mocks);
    const record = makeEscrowDepositedRaw(100, "100-1");
    mockHorizonPage([record]);

    const result = await svc.indexLedgerRange(CONTRACT_ID, 100, 100);

    expect(result.processed).toBe(1);
    expect(result.persisted).toBe(1);
    expect(mocks.escrowRepo.upsertEvent).toHaveBeenCalledTimes(1);
    expect(mocks.checkpointRepo.saveLastLedger).toHaveBeenCalledWith(CONTRACT_ID, 100);
    expect(mocks.eventEmitter.emit).toHaveBeenCalledWith("stellar.EscrowDeposited", expect.anything());
  });

  it("skips already-indexed range when checkpoint is ahead", async () => {
    const mocks = buildMocks();
    (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(200);
    const svc = buildService(mocks);
    mockHorizonPage([]);

    const result = await svc.indexLedgerRange(CONTRACT_ID, 100, 200);

    expect(result.processed).toBe(0);
    expect(mocks.escrowRepo.upsertEvent).not.toHaveBeenCalled();
  });

  it("force=true reprocesses the full range ignoring checkpoint", async () => {
    const mocks = buildMocks();
    (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(200);
    const svc = buildService(mocks);
    const record = makeEscrowDepositedRaw(100, "100-1");
    mockHorizonPage([record]);

    const result = await svc.indexLedgerRange(CONTRACT_ID, 100, 200, true);

    expect(result.processed).toBe(1);
    expect(mocks.escrowRepo.upsertEvent).toHaveBeenCalledTimes(1);
  });

  it("counts skipped unknown-schema events separately", async () => {
    const mocks = buildMocks();
    const svc = buildService(mocks);

    // Build a raw event with schema_version=99 (unsupported)
    const topics = [
      symVal("EscrowDeposited"),
      xdr.ScVal.scvBytes(Buffer.from(COMMITMENT_HEX, "hex")),
      nativeToScVal(OWNER),
    ];
    const data = mapVal({
      schema_version: nativeToScVal(99, { type: "u32" }),
      token: nativeToScVal(TOKEN),
      amount: nativeToScVal(1_000n, { type: "i128" }),
      expires_at: nativeToScVal(9999999n, { type: "u64" }),
      timestamp: nativeToScVal(1700000000n, { type: "u64" }),
    });
    const raw: RawHorizonContractEvent = {
      id: "1",
      paging_token: "100-1",
      transaction_hash: "tx1",
      ledger: 100,
      created_at: "2026-01-01T00:00:00Z",
      contract_id: CONTRACT_ID,
      type: "contract",
      topic: topics.map((v) => v.toXDR("base64")),
      value: { xdr: data.toXDR("base64") },
    };

    mockHorizonPage([raw]);

    const result = await svc.indexLedgerRange(CONTRACT_ID, 100, 100);

    expect(result.processed).toBe(1);
    expect(result.persisted).toBe(0);
    expect(result.skippedUnknownSchema).toBe(1);
    expect(mocks.escrowRepo.upsertEvent).not.toHaveBeenCalled();
    expect(mocks.metrics.recordUnknownSchemaVersion).toHaveBeenCalledWith("EscrowDeposited", 99);
  });

  it("is idempotent: calling twice with same range does not double-persist", async () => {
    const mocks = buildMocks();
    // First call: no checkpoint
    (mocks.checkpointRepo.getLastLedger as jest.Mock)
      .mockResolvedValueOnce(null)   // first call
      .mockResolvedValueOnce(100);   // second call: checkpoint is at 100

    const svc = buildService(mocks);
    const record = makeEscrowDepositedRaw(100, "100-1");
    mockHorizonPage([record]);

    await svc.indexLedgerRange(CONTRACT_ID, 100, 100);
    // Second call: checkpoint says 100, range is [100,100] → effectiveFrom=101 > toLedger=100 → skip
    const result2 = await svc.indexLedgerRange(CONTRACT_ID, 100, 100);

    expect(result2.processed).toBe(0);
    // upsertEvent called only once across both runs
    expect(mocks.escrowRepo.upsertEvent).toHaveBeenCalledTimes(1);
  });
});
