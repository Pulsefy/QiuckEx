// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

import { TestnetHealthConsole } from "../admin/TestnetHealthConsole";
import {
  stellarExpertContractUrl,
  SECTION_SEVERITY,
} from "../admin/TestnetHealthCards";
import type { RcValidationReport } from "../admin/testnet-health.types";

vi.mock("@/lib/api", () => ({
  getQuickexApiBase: () => "http://test-api.local",
}));

const report: RcValidationReport = {
  reportId: "report-1",
  generatedAt: "2026-08-25T12:00:00.000Z",
  network: "testnet",
  environment: "staging",
  releaseReady: false,
  overallStatus: "blocked",
  sections: {
    smoke: {
      status: "fail",
      ready: false,
      checks: [
        { name: "database", status: "up" },
        { name: "horizon", status: "down", error: "Horizon returned 503" },
      ],
      passed: 1,
      failed: 1,
    },
    registry: {
      status: "pass",
      network: "testnet",
      authoritative: true,
      version: 4,
      activeContracts: 1,
      expectedContracts: ["quickex"],
      missingContracts: [],
    },
    lag: {
      status: "warning",
      currentNetworkLedger: 5000,
      lastIndexedLedger: 4950,
      lagLedgers: 50,
      isLagging: true,
      isBlocking: false,
      thresholdLedgers: 100,
    },
    environment: {
      status: "pass",
      checks: [{ check: "network_configuration", status: "pass", details: "Network: testnet" }],
      passed: 1,
      failed: 0,
      warnings: 0,
    },
  },
  blockers: [
    {
      id: "smoke.horizon.down",
      severity: "critical",
      category: "smoke",
      message: "Smoke check 'horizon' failed: Horizon returned 503",
      remediation: "Restore horizon before releasing",
      detectedAt: "2026-08-25T12:00:00.000Z",
    },
    {
      id: "lag.lagging",
      severity: "warning",
      category: "lag",
      message: "Indexer is lagging by 50 ledgers",
      detectedAt: "2026-08-25T12:00:00.000Z",
    },
    {
      id: "lag.unknown",
      severity: "info",
      category: "environment",
      message: "Parity advisory",
      detectedAt: "2026-08-25T12:00:00.000Z",
    },
  ],
  summary: { critical: 1, warning: 1, info: 1 },
};

const deploymentsResponse = {
  network: "testnet",
  deployments: [
    {
      name: "quickex",
      network: "testnet",
      contractId: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
      wasmHash: "0xabc123",
      contractVersion: 3,
      schemaVersion: "1.2.0",
      updatedAt: "2026-08-24T10:00:00.000Z",
      registryVersion: 4,
      deploymentId: "deploy-2026-08-24",
    },
  ],
};

function jsonResponse(body: unknown, ok = true) {
  return {
    ok,
    status: ok ? 200 : 500,
    json: async () => body,
  } as Response;
}

describe("TestnetHealthConsole", () => {
  beforeEach(() => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/admin/rc-validation/report")) {
        return jsonResponse(report);
      }
      if (url.includes("/contracts/registry/deployments")) {
        return jsonResponse(deploymentsResponse);
      }
      return jsonResponse({}, false);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders overall readiness and section panels from the backend report", async () => {
    render(<TestnetHealthConsole />);

    expect(await screen.findByText("Blocked")).toBeInTheDocument();
    expect(screen.getByText("Contract Registry")).toBeInTheDocument();
    expect(screen.getByText("Indexer Lag")).toBeInTheDocument();
    expect(screen.getByText("Smoke Runs")).toBeInTheDocument();
    expect(screen.getByText("Environment Metadata")).toBeInTheDocument();
    expect(screen.getByText("quickex")).toBeInTheDocument();
  });

  it("shows blocker rows with severity pills sorted critical first", async () => {
    render(<TestnetHealthConsole />);
    await screen.findByText("Blocked");

    const rows = screen.getAllByRole("row");
    const severityCells = rows
      .slice(1)
      .map((row) => row.textContent ?? "")
      .filter((text) => text.includes("critical") || text.includes("warning") || text.includes("info"));
    expect(severityCells[0]).toContain("critical");
    expect(screen.getByText(/Fix: Restore horizon before releasing/i)).toBeInTheDocument();
  });

  it("filters blockers by selected severity", async () => {
    render(<TestnetHealthConsole />);
    await screen.findByText("Blocked");

    fireEvent.click(screen.getByRole("button", { name: /warning \(1\)/i }));
    expect(screen.getByText(/Indexer is lagging by 50 ledgers/i)).toBeInTheDocument();
    expect(screen.queryByText(/Smoke check 'horizon' failed/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /all \(3\)/i }));
    expect(screen.getByText(/Smoke check 'horizon' failed/i)).toBeInTheDocument();
  });

  it("links registry entries, transactions and webhook log pages", async () => {
    render(<TestnetHealthConsole />);
    await screen.findByText("Blocked");

    const expectedHref = stellarExpertContractUrl(
      "testnet",
      "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
    );
    expect(screen.getByTitle(deploymentsResponse.deployments[0].contractId)).toHaveAttribute(
      "href",
      expectedHref,
    );
    const dashboardLinks = screen.getAllByRole("link", { name: /recent transactions/i });
    dashboardLinks.forEach((link) =>
      expect(link).toHaveAttribute("href", "/dashboard"),
    );
    expect(screen.getByRole("link", { name: /webhook delivery logs/i })).toHaveAttribute(
      "href",
      "/webhooks",
    );
    expect(screen.getAllByRole("link", { name: /view panel/i }).length).toBe(3);
  });

  it("shows an error banner with retry when the report endpoint fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({}, false)),
    );
    render(<TestnetHealthConsole />);

    const retryButton = await screen.findByRole("button", { name: /retry/i });
    expect(retryButton).toBeInTheDocument();

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).includes("/admin/rc-validation/report")
          ? jsonResponse(report)
          : jsonResponse(deploymentsResponse),
      ),
    );
    fireEvent.click(retryButton);
    await waitFor(() => expect(screen.getByText("Blocked")).toBeInTheDocument());
  });
});

describe("testnet health helpers", () => {
  it("maps section statuses to severities", () => {
    expect(SECTION_SEVERITY.pass).toBe("none");
    expect(SECTION_SEVERITY.fail).toBe("critical");
    expect(SECTION_SEVERITY.warning).toBe("warning");
    expect(SECTION_SEVERITY.unknown).toBe("warning");
  });

  it("builds network-aware explorer urls for registry entries", () => {
    expect(stellarExpertContractUrl("testnet", "ABC")).toBe(
      "https://stellar.expert/explorer/testnet/contract/ABC",
    );
    expect(stellarExpertContractUrl("mainnet", "DEF")).toBe(
      "https://stellar.expert/explorer/mainnet/contract/DEF",
    );
  });
});
