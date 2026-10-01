import { EventEmitter2 } from "@nestjs/event-emitter";
import { AppConfigService } from "../config";
import { SupabaseService } from "../supabase/supabase.service";
import { ContractRegistryService } from "./contract-registry.service";
import { ContractSpecService } from "./contract-spec.service";

describe("ContractSpecService.fetchAndStoreSpec", () => {
  let service: ContractSpecService;
  let mockSupabaseService: jest.Mocked<Partial<SupabaseService>>;
  let mockConfigService: Partial<AppConfigService>;
  let mockRegistryService: jest.Mocked<Partial<ContractRegistryService>>;
  let mockEventEmitter: jest.Mocked<EventEmitter2>;
  let insertMock: jest.Mock;

  const deployment = {
    name: "quickex",
    network: "testnet",
    networkPassphrase: "Test SDF Network ; September 2015",
    contractId: "CABC123",
    wasmHash: "wasm-hash-1",
    contractVersion: 2,
    schemaVersion: "1.0.0",
    schemaCompatibility: { min: "1.0.0", max: "1.0.0" },
    initParams: {},
    metadata: {},
    updatedAt: new Date().toISOString(),
    registryVersion: 1,
  };

  const specPayload = {
    schemaVersion: "1.1.0",
    methods: [
      { name: "transfer", args: ["from", "to", "amount"], returns: "bool" },
    ],
    events: [{ name: "Transfer", fields: ["from", "to", "amount"] }],
    storage: [{ name: "Balance", fields: ["address"] }],
    metadata: { source: "rpc" },
  };

  const encodeSpec = (payload: unknown) =>
    Buffer.from(JSON.stringify(payload), "utf8").toString("base64");

  beforeEach(() => {
    insertMock = jest.fn().mockResolvedValue({ error: null });

    const mockClient = {
      from: jest.fn(() => ({
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        single: jest.fn().mockResolvedValue({ data: null, error: null }),
        insert: insertMock,
      })),
    };

    mockSupabaseService = {
      getClient: jest.fn(() => mockClient as never),
    };

    mockConfigService = {
      network: "testnet",
      sorobanRpcUrl: "https://soroban-testnet.stellar.org",
    } as Partial<AppConfigService>;

    mockRegistryService = {
      getDeploymentByName: jest.fn().mockResolvedValue(deployment),
    } as unknown as jest.Mocked<Partial<ContractRegistryService>>;

    mockEventEmitter = {
      emit: jest.fn(),
    } as unknown as jest.Mocked<EventEmitter2>;

    service = new ContractSpecService(
      mockSupabaseService as unknown as SupabaseService,
      mockConfigService as AppConfigService,
      mockRegistryService as unknown as ContractRegistryService,
      mockEventEmitter,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("fetches the spec over RPC and persists it", async () => {
    const fetchMock = jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        result: { returnValue: { xdr: encodeSpec(specPayload) } },
      }),
    } as unknown as Response);

    const result = await (service as unknown as {
      fetchAndStoreSpec: (name: string) => Promise<unknown>;
    }).fetchAndStoreSpec("quickex");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result).toEqual(
      expect.objectContaining({
        contractName: "quickex",
        contractId: "CABC123",
        schemaVersion: "1.1.0",
        methods: specPayload.methods,
        events: specPayload.events,
        storage: specPayload.storage,
      }),
    );

    // Persisted via the existing persistSpec path.
    expect(insertMock).toHaveBeenCalledTimes(1);
    expect(insertMock).toHaveBeenCalledWith(
      expect.objectContaining({
        contract_name: "quickex",
        contract_id: "CABC123",
        schema_version: "1.1.0",
      }),
    );

    // Cached via updateCache so subsequent reads are served from memory.
    const cached = await (service as unknown as {
      getSpecRecord: (name: string) => Promise<unknown>;
    }).getSpecRecord("quickex");
    expect(cached).toEqual(expect.objectContaining({ contractName: "quickex" }));
  });

  it("degrades gracefully when the contract has no spec yet", async () => {
    jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ result: { error: "missing spec" } }),
    } as unknown as Response);

    const result = await (service as unknown as {
      fetchAndStoreSpec: (name: string) => Promise<unknown>;
    }).fetchAndStoreSpec("quickex");

    expect(result).toBeNull();
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("degrades gracefully when the RPC call fails", async () => {
    jest.spyOn(global, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));

    const result = await (service as unknown as {
      fetchAndStoreSpec: (name: string) => Promise<unknown>;
    }).fetchAndStoreSpec("quickex");

    expect(result).toBeNull();
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("returns null when the contract is not registered", async () => {
    mockRegistryService.getDeploymentByName = jest
      .fn()
      .mockRejectedValue(new Error("not found"));
    const fetchMock = jest.spyOn(global, "fetch");

    const result = await (service as unknown as {
      fetchAndStoreSpec: (name: string) => Promise<unknown>;
    }).fetchAndStoreSpec("unknown");

    expect(result).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
