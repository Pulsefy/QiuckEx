import { HealthService } from "./health.service";

describe("HealthService", () => {
  let service: HealthService;
  let fetchSpy: jest.SpyInstance;

  let supabase: {
    checkHealth: jest.Mock;
    getClient: jest.Mock;
  };
  let horizon: { getBaseUrl: jest.Mock };
  let config: {
    supabaseUrl: string;
    supabaseAnonKey: string;
    network: string;
    isPaymentSigningConfigured: boolean;
  };
  let jobQueueService: Record<string, jest.Mock>;
  let jobRepository: { listJobs: jest.Mock };
  let cursorRepository: { getCursor: jest.Mock };
  let sorobanRpc: { getNetworkPassphrase: jest.Mock };

  function healthySupabaseClient() {
    const resolveNoError = jest.fn().mockResolvedValue({ error: null });
    return {
      from: jest.fn(() => ({
        select: jest.fn(() => ({
          order: jest.fn(() => ({ limit: resolveNoError })),
          limit: resolveNoError,
        })),
      })),
    };
  }

  function failingSupabaseClient() {
    const resolveError = jest
      .fn()
      .mockResolvedValue({ error: { message: "db unreachable" } });
    return {
      from: jest.fn(() => ({
        select: jest.fn(() => ({
          order: jest.fn(() => ({ limit: resolveError })),
          limit: resolveError,
        })),
      })),
    };
  }

  function buildService(): HealthService {
    return new HealthService(
      supabase as never,
      horizon as never,
      config as never,
      jobQueueService as never,
      jobRepository as never,
      cursorRepository as never,
      sorobanRpc as never,
    );
  }

  beforeEach(() => {
    jest.useFakeTimers();

    supabase = {
      checkHealth: jest.fn().mockResolvedValue(true),
      getClient: jest.fn(healthySupabaseClient),
    };
    horizon = {
      getBaseUrl: jest.fn().mockReturnValue("https://horizon.example.com"),
    };
    config = {
      supabaseUrl: "https://db.example.com",
      supabaseAnonKey: "anon-key",
      network: "testnet",
      isPaymentSigningConfigured: false,
    };
    jobQueueService = {};
    jobRepository = { listJobs: jest.fn().mockResolvedValue([]) };
    cursorRepository = { getCursor: jest.fn().mockResolvedValue(null) };
    sorobanRpc = {
      getNetworkPassphrase: jest
        .fn()
        .mockResolvedValue("Test SDF Network ; September 2015"),
    };

    fetchSpy = jest
      .spyOn(global, "fetch")
      .mockResolvedValue({ ok: true, status: 200 } as Response);

    service = buildService();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe("liveness (getHealthStatus)", () => {
    it("reports the process is alive without touching any external service", async () => {
      const status = await service.getHealthStatus();

      expect(status).toEqual({
        status: "ok",
        version: expect.any(String),
        uptime: expect.any(Number),
      });

      expect(supabase.checkHealth).not.toHaveBeenCalled();
      expect(supabase.getClient).not.toHaveBeenCalled();
      expect(horizon.getBaseUrl).not.toHaveBeenCalled();
      expect(sorobanRpc.getNetworkPassphrase).not.toHaveBeenCalled();
      expect(jobRepository.listJobs).not.toHaveBeenCalled();
      expect(cursorRepository.getCursor).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe("readiness (getReadinessStatus) — all healthy", () => {
    it("reports ready with every dependency up", async () => {
      const result = await service.getReadinessStatus();

      expect(result.ready).toBe(true);
      expect(result.degraded).toBe(false);

      const names = result.checks.map((c) => c.name);
      expect(names).toEqual(
        expect.arrayContaining([
          "supabase",
          "environment",
          "migrations",
          "queue",
          "horizon",
          "soroban_rpc",
          "ingestion",
        ]),
      );

      for (const check of result.checks) {
        expect(check.status).toBe("up");
      }
    });
  });

  describe("readiness — each critical dependency failing independently", () => {
    const cases: Array<{
      name: string;
      checkName: string;
      fail: () => void;
    }> = [
      {
        name: "database (supabase)",
        checkName: "supabase",
        fail: () => supabase.checkHealth.mockResolvedValue(false),
      },
      {
        name: "migrations",
        checkName: "migrations",
        fail: () => supabase.getClient.mockImplementation(failingSupabaseClient),
      },
      {
        name: "job queue",
        checkName: "queue",
        fail: () =>
          jobRepository.listJobs.mockRejectedValue(new Error("queue down")),
      },
      {
        name: "horizon",
        checkName: "horizon",
        fail: () =>
          fetchSpy.mockRejectedValue(new Error("connection refused")),
      },
      {
        name: "soroban rpc",
        checkName: "soroban_rpc",
        fail: () =>
          sorobanRpc.getNetworkPassphrase.mockRejectedValue(
            new Error("rpc 503 unavailable"),
          ),
      },
    ];

    it.each(cases)(
      "is not ready when $name is down",
      async ({ checkName, fail }) => {
        fail();

        const result = await service.getReadinessStatus();

        expect(result.ready).toBe(false);

        const failed = result.checks.find((c) => c.name === checkName);
        expect(failed?.status).toBe("down");
        expect(failed?.error).toBeDefined();
      },
    );
  });

  describe("readiness — degraded vs hard failure", () => {
    it("marks a timed-out dependency as degraded but stays ready", async () => {
      sorobanRpc.getNetworkPassphrase.mockRejectedValue(new Error("Timeout"));

      const result = await service.getReadinessStatus();

      expect(result.ready).toBe(true);
      expect(result.degraded).toBe(true);

      const soroban = result.checks.find((c) => c.name === "soroban_rpc");
      expect(soroban?.status).toBe("degraded");
    });

    it("distinguishes a timed-out dependency (degraded) from a hard failure (down)", async () => {
      fetchSpy.mockRejectedValue(new Error("Timeout"));
      sorobanRpc.getNetworkPassphrase.mockRejectedValue(
        new Error("rpc unreachable"),
      );

      const result = await service.getReadinessStatus();

      expect(result.ready).toBe(false);
      expect(result.degraded).toBe(true);

      const horizonCheck = result.checks.find((c) => c.name === "horizon");
      const sorobanCheck = result.checks.find((c) => c.name === "soroban_rpc");
      expect(horizonCheck?.status).toBe("degraded");
      expect(sorobanCheck?.status).toBe("down");
    });

    it("reports degraded per-dependency status even when still ready", async () => {
      fetchSpy.mockRejectedValue(new Error("Timeout"));

      const result = await service.getReadinessStatus();

      expect(result.ready).toBe(true);
      expect(result.degraded).toBe(true);

      const horizonCheck = result.checks.find((c) => c.name === "horizon");
      expect(horizonCheck?.status).toBe("degraded");
    });
  });
});
