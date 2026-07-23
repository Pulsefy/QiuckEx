/**
 * Tests for deployment-info.ts helpers.
 *
 * These run in a Node environment (no DOM required) because the helpers
 * only read process.env and perform pure logic.
 */

import {
  getDeploymentInfo,
  isDiagnosticsPanelVisible,
  type DeploymentInfo,
} from "@/lib/deployment-info";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Save and restore process.env around each test. */
const originalEnv = process.env;

beforeEach(() => {
  jest.resetModules();
  process.env = { ...originalEnv };
});

afterEach(() => {
  process.env = originalEnv;
});

// ---------------------------------------------------------------------------
// getDeploymentInfo
// ---------------------------------------------------------------------------

describe("getDeploymentInfo", () => {
  it("returns all null / default values when no env vars are set", () => {
    delete process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF;
    delete process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA;
    delete process.env.NEXT_PUBLIC_VERCEL_DEPLOYED_AT;
    delete process.env.NEXT_PUBLIC_QUICKEX_API_URL;
    delete process.env.NEXT_PUBLIC_STELLAR_NETWORK;
    delete process.env.NEXT_PUBLIC_VERCEL_ENV;
    delete process.env.NEXT_PUBLIC_VERCEL_URL;
    delete process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION;
    delete process.env.NEXT_PUBLIC_APP_VERSION;

    const info = getDeploymentInfo();

    expect(info.branch).toBeNull();
    expect(info.commitSha).toBeNull();
    expect(info.commitShort).toBeNull();
    expect(info.deployedAt).toBeNull();
    expect(info.apiUrl).toBe("http://localhost:4000");
    expect(info.network).toBe("testnet");
    expect(info.vercelEnv).toBeNull();
    expect(info.vercelUrl).toBeNull();
    expect(info.contractRegistryVersion).toBeNull();
    expect(info.appVersion).toBeNull();
  });

  it("reads all env vars correctly when they are set", () => {
    process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF = "feat/preview-diagnostics";
    process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA =
      "abcdef1234567890abcdef1234567890abcdef12";
    process.env.NEXT_PUBLIC_VERCEL_DEPLOYED_AT = "2026-07-23T15:00:00Z";
    process.env.NEXT_PUBLIC_QUICKEX_API_URL = "https://api.quickex.to/";
    process.env.NEXT_PUBLIC_STELLAR_NETWORK = "mainnet";
    process.env.NEXT_PUBLIC_VERCEL_ENV = "preview";
    process.env.NEXT_PUBLIC_VERCEL_URL = "quickex-abc123.vercel.app";
    process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION = "v2.3.1";
    process.env.NEXT_PUBLIC_APP_VERSION = "1.4.0";

    const info = getDeploymentInfo();

    expect(info.branch).toBe("feat/preview-diagnostics");
    expect(info.commitSha).toBe("abcdef1234567890abcdef1234567890abcdef12");
    expect(info.commitShort).toBe("abcdef1");
    expect(info.deployedAt).toBe("2026-07-23T15:00:00Z");
    // Trailing slash must be stripped
    expect(info.apiUrl).toBe("https://api.quickex.to");
    expect(info.network).toBe("mainnet");
    expect(info.vercelEnv).toBe("preview");
    expect(info.vercelUrl).toBe("quickex-abc123.vercel.app");
    expect(info.contractRegistryVersion).toBe("v2.3.1");
    expect(info.appVersion).toBe("1.4.0");
  });

  it("derives a 7-char commitShort from commitSha", () => {
    process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA =
      "0123456789abcdef0123456789abcdef01234567";

    const { commitShort } = getDeploymentInfo();

    expect(commitShort).toBe("0123456");
  });

  it("strips trailing slash from apiUrl", () => {
    process.env.NEXT_PUBLIC_QUICKEX_API_URL = "https://api.example.com/";

    const { apiUrl } = getDeploymentInfo();

    expect(apiUrl).toBe("https://api.example.com");
  });
});

// ---------------------------------------------------------------------------
// isDiagnosticsPanelVisible
// ---------------------------------------------------------------------------

describe("isDiagnosticsPanelVisible", () => {
  const base: DeploymentInfo = {
    branch: null,
    commitSha: null,
    commitShort: null,
    deployedAt: null,
    apiUrl: "http://localhost:4000",
    network: "testnet",
    vercelEnv: null,
    vercelUrl: null,
    contractRegistryVersion: null,
    appVersion: null,
  };

  it("is visible on testnet + preview (typical PR preview deploy)", () => {
    expect(
      isDiagnosticsPanelVisible({ ...base, network: "testnet", vercelEnv: "preview" }),
    ).toBe(true);
  });

  it("is visible on mainnet + preview (e.g. a mainnet preview branch)", () => {
    expect(
      isDiagnosticsPanelVisible({ ...base, network: "mainnet", vercelEnv: "preview" }),
    ).toBe(true);
  });

  it("is visible on testnet + production", () => {
    expect(
      isDiagnosticsPanelVisible({
        ...base,
        network: "testnet",
        vercelEnv: "production",
      }),
    ).toBe(true);
  });

  it("is visible when vercelEnv is null (local development)", () => {
    expect(
      isDiagnosticsPanelVisible({ ...base, network: "mainnet", vercelEnv: null }),
    ).toBe(true);
  });

  it("is visible on testnet with no vercelEnv", () => {
    expect(
      isDiagnosticsPanelVisible({ ...base, network: "testnet", vercelEnv: null }),
    ).toBe(true);
  });

  it("is HIDDEN on mainnet + production Vercel deploy", () => {
    expect(
      isDiagnosticsPanelVisible({
        ...base,
        network: "mainnet",
        vercelEnv: "production",
      }),
    ).toBe(false);
  });
});
