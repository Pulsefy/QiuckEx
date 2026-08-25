"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";

import {
  EnvironmentMetaCard,
  IndexerLagCard,
  RegistryStatusCard,
  SECTION_SEVERITY,
  SmokeRunsCard,
} from "./TestnetHealthCards";
import type {
  ContractDeploymentsResponse,
  ContractDeploymentItem,
  RcBlocker,
  RcBlockerCategory,
  RcBlockerSeverity,
  RcOverallStatus,
  RcValidationReport,
  SeverityFilter,
} from "./testnet-health.types";

const REFRESH_INTERVAL_MS = 60_000;

const OVERALL_STYLES: Record<RcOverallStatus, string> = {
  ready: "bg-success-soft text-success",
  degraded: "bg-warning-soft text-warning",
  blocked: "bg-danger-soft text-danger",
};

const OVERALL_LABEL: Record<RcOverallStatus, string> = {
  ready: "Release ready",
  degraded: "Degraded",
  blocked: "Blocked",
};

const SEVERITY_PILL_CLASSES: Record<RcBlockerSeverity, string> = {
  critical: "bg-danger-soft text-danger border border-danger",
  warning: "bg-warning-soft text-warning border border-warning",
  info: "bg-surface text-muted border border-border-strong",
};

const CATEGORY_ANCHORS: Record<RcBlockerCategory, string> = {
  smoke: "#th-smoke",
  registry: "#th-registry",
  lag: "#th-lag",
  environment: "#th-environment",
};

const FILTERS: SeverityFilter[] = ["all", "critical", "warning", "info"];

function categoryAnchor(category: RcBlockerCategory): string {
  return CATEGORY_ANCHORS[category] ?? "#th-smoke";
}

export function TestnetHealthConsole() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const [report, setReport] = useState<RcValidationReport | null>(null);
  const [deployments, setDeployments] = useState<ContractDeploymentItem[]>([]);
  const [deploymentsError, setDeploymentsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(
    async (showSpinner: boolean) => {
      if (showSpinner) setRefreshing(true);
      try {
        setError(null);
        const [reportResponse, deploymentsResponse] = await Promise.all([
          fetch(`${apiBase}/admin/rc-validation/report`, { cache: "no-store" }),
          fetch(`${apiBase}/contracts/registry/deployments`, {
            cache: "no-store",
          }),
        ]);

        if (!reportResponse.ok) {
          throw new Error(`Health report fetch failed (${reportResponse.status})`);
        }
        const payload = (await reportResponse.json()) as RcValidationReport;
        setReport(payload);

        if (deploymentsResponse.ok) {
          const deploymentPayload =
            (await deploymentsResponse.json()) as ContractDeploymentsResponse;
          setDeployments(deploymentPayload.deployments ?? []);
          setDeploymentsError(null);
        } else {
          setDeployments([]);
          setDeploymentsError(
            `Deployment metadata unavailable (${deploymentsResponse.status})`,
          );
        }
      } catch (fetchError) {
        setError(
          fetchError instanceof Error
            ? fetchError.message
            : "Unable to load testnet health data.",
        );
      } finally {
        setLoading(false);
        if (showSpinner) setRefreshing(false);
      }
    },
    [apiBase],
  );

  useEffect(() => {
    void load(false);
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => void load(false), REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [autoRefresh, load]);

  const filteredBlockers: RcBlocker[] = useMemo(() => {
    if (!report) return [];
    const ordered: Record<RcBlockerSeverity, number> = {
      critical: 0,
      warning: 1,
      info: 2,
    };
    return [...report.blockers]
      .sort((left, right) => ordered[left.severity] - ordered[right.severity])
      .filter((blocker) => filter === "all" || blocker.severity === filter);
  }, [report, filter]);

  const summary = report?.summary ?? { critical: 0, warning: 0, info: 0 };
  const totalBlockers = summary.critical + summary.warning + summary.info;

  const isCardDimmed = (status: keyof typeof SECTION_SEVERITY): boolean => {
    if (filter === "all") return false;
    return SECTION_SEVERITY[status] !== filter;
  };


  return (
    <div className="space-y-6">
      <div className="bg-card rounded-lg shadow-sm border border-border p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-foreground">
              Testnet Health Console
            </h2>
            <p className="text-sm text-subtle">
              One view of contract registry status, indexer lag, smoke runs and
              environment metadata for release readiness.
            </p>
            {report && (
              <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-subtle">
                <span className="rounded-full bg-brand-soft px-2 py-0.5 font-semibold uppercase tracking-wide text-brand">
                  {report.network}
                </span>
                <span className="rounded-full bg-surface px-2 py-0.5 font-semibold uppercase tracking-wide text-muted">
                  {report.environment}
                </span>
                <span>Updated {new Date(report.generatedAt).toLocaleTimeString()}</span>
              </p>
            )}
          </div>

          <div className="flex flex-col items-end gap-2">
            {report && (
              <span
                className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold ${OVERALL_STYLES[report.overallStatus]}`}
                role="status"
              >
                <span
                  className={`h-2 w-2 rounded-full ${
                    report.overallStatus === "ready"
                      ? "bg-success"
                      : report.overallStatus === "degraded"
                        ? "bg-warning"
                        : "bg-danger"
                  }`}
                />
                {OVERALL_LABEL[report.overallStatus]}
              </span>
            )}
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1.5 text-xs text-subtle">
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5"
                  checked={autoRefresh}
                  onChange={(event) => setAutoRefresh(event.target.checked)}
                />
                Auto-refresh
              </label>
              <button
                type="button"
                onClick={() => void load(true)}
                disabled={refreshing}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-muted hover:text-foreground hover:bg-background disabled:opacity-50"
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
                />
                Refresh
              </button>
            </div>
          </div>
        </div>

        {error && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-danger bg-danger-soft px-3 py-2 text-sm text-danger">
            <span className="inline-flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              {error}
            </span>
            <button
              type="button"
              onClick={() => void load(true)}
              className="rounded-md border border-danger px-2 py-1 text-xs font-semibold hover:bg-card"
            >
              Retry
            </button>
          </div>
        )}

        {loading && !report ? (
          <p className="py-10 text-center text-sm text-subtle" role="status">
            Loading testnet health…
          </p>
        ) : report ? (
          <>
            <div
              role="group"
              aria-label="Filter blockers by severity"
              className="flex flex-wrap items-center gap-2"
            >
              <span className="text-xs font-semibold uppercase tracking-wide text-subtle">
                Severity:
              </span>
              {FILTERS.map((option) => {
                const count = option === "all" ? totalBlockers : summary[option];
                const active = filter === option;
                return (
                  <button
                    key={option}
                    type="button"
                    onClick={() => setFilter(option)}
                    aria-pressed={active}
                    className={`rounded-full px-3 py-1 text-xs font-semibold capitalize transition ${
                      active
                        ? "bg-brand text-white"
                        : "bg-surface text-muted hover:text-foreground border border-border"
                    }`}
                  >
                    {option === "critical" ? "Blockers" : option} ({count})
                  </button>
                );
              })}
            </div>

            {filteredBlockers.length === 0 ? (
              <p className="rounded-md border border-border bg-background px-3 py-4 text-center text-sm text-subtle">
                {filter === "all"
                  ? "No blockers reported — all checks passed."
                  : `No ${filter === "critical" ? "critical blockers" : `${filter} signals`} in the latest report.`}
              </p>
            ) : (
              <div className="overflow-x-auto rounded-md border border-border">
                <table className="w-full text-left text-sm text-muted">
                  <thead className="text-xs uppercase bg-background border-b border-border text-subtle">
                    <tr>
                      <th className="px-4 py-3 rounded-tl-lg">Severity</th>
                      <th className="px-4 py-3">Area</th>
                      <th className="px-4 py-3">Detail</th>
                      <th className="px-4 py-3">Detected</th>
                      <th className="px-4 py-3 rounded-tr-lg">Inspect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredBlockers.map((blocker) => (
                      <tr
                        key={blocker.id}
                        className="border-b border-border last:border-0 align-top hover:bg-background"
                      >
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${SEVERITY_PILL_CLASSES[blocker.severity]}`}
                          >
                            {blocker.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap capitalize">
                          {blocker.category}
                        </td>
                        <td className="px-4 py-3">
                          <p className="font-medium text-foreground">
                            {blocker.message}
                          </p>
                          {blocker.remediation && (
                            <p className="mt-0.5 text-xs text-subtle">
                              Fix: {blocker.remediation}
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-xs text-subtle">
                          {new Date(blocker.detectedAt).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <a
                            href={categoryAnchor(blocker.category)}
                            className="text-sm font-medium text-brand hover:underline"
                          >
                            View panel
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        ) : null}
      </div>

      {report && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <RegistryStatusCard
            section={report.sections.registry}
            deployments={deployments}
            deploymentsError={deploymentsError}
            dimmed={isCardDimmed(report.sections.registry.status)}
          />
          <IndexerLagCard
            section={report.sections.lag}
            dimmed={isCardDimmed(report.sections.lag.status)}
          />
          <SmokeRunsCard
            section={report.sections.smoke}
            dimmed={isCardDimmed(report.sections.smoke.status)}
          />
          <EnvironmentMetaCard
            network={report.network}
            environment={report.environment}
            generatedAt={report.generatedAt}
            releaseReady={report.releaseReady}
            section={report.sections.environment}
            dimmed={isCardDimmed(report.sections.environment.status)}
          />
        </div>
      )}
    </div>
  );
}
