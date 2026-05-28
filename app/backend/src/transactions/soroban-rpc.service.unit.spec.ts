import { ConfigService } from "@nestjs/config";
import { MetricsService } from "../metrics/metrics.service";
import { SorobanRpcService } from "./soroban-rpc.service";

describe("SorobanRpcService", () => {
  function createConfig(overrides: Record<string, unknown> = {}) {
    const values: Record<string, unknown> = {
      "stellar.sorobanRpcUrl": "https://rpc-1.example.com",
      "stellar.sorobanRpcUrls": [
        "https://rpc-1.example.com",
        "https://rpc-2.example.com",
      ],
      SOROBAN_RPC_TIMEOUT_MS: "50",
      SOROBAN_RPC_MAX_RETRIES: "2",
      ...overrides,
    };

    return {
      get: jest.fn((key: string) => values[key]),
    } as unknown as ConfigService;
  }

  function createMetrics() {
    return {
      setSorobanRpcActiveEndpoint: jest.fn(),
      recordSorobanRpcFailover: jest.fn(),
      recordExternalCall: jest.fn(),
      recordError: jest.fn(),
    } as unknown as MetricsService;
  }

  it("fails over to secondary RPC endpoint on transient error", async () => {
    const service = new SorobanRpcService(createConfig(), createMetrics());
    const firstServer = {
      getNetwork: jest.fn().mockRejectedValue(new Error("network timeout")),
    };
    const secondServer = {
      getNetwork: jest.fn().mockResolvedValue({ passphrase: "TESTNET" }),
    };
    const serviceInternals = service as unknown as { createServer: jest.Mock };

    serviceInternals.createServer = jest
      .fn()
      .mockReturnValueOnce(firstServer)
      .mockReturnValueOnce(secondServer);

    await expect(service.getNetworkPassphrase()).resolves.toBe("TESTNET");
    expect(serviceInternals.createServer).toHaveBeenCalledTimes(2);
  });

  it("throws after max retries for persistent transient failures", async () => {
    const service = new SorobanRpcService(createConfig(), createMetrics());
    const serviceInternals = service as unknown as { createServer: jest.Mock };
    serviceInternals.createServer = jest.fn().mockReturnValue({
      getNetwork: jest.fn().mockRejectedValue(new Error("503 unavailable")),
    });

    await expect(service.getNetworkPassphrase()).rejects.toThrow("503");
    expect(serviceInternals.createServer).toHaveBeenCalledTimes(2);
  });
});
