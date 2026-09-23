"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Filter,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { getQuickexApiBase } from "@/lib/api";
import { getDeploymentInfo } from "@/lib/deployment-info";
import type {
  Blocker,
  HealthReport,
  OverallStatus,
  Severity,
} from "@/types/health-console";
import {
  ErrorState,
  LoadingSkeleton,
  formatDateTime,
  overallStatusLabel,
  overallStatusToTone,
  SeverityPill,
  SeverityTone,
  SeverityDot,
} from "./HealthBadges";
import { SummaryCard } from "./SummaryCard";
import { RegistryPanel } from "./RegistryPanel";
import { IndexerLagPanel } from "./IndexerLagPanel";
import { SmokeTestPanel } from "./SmokeTestPanel";
import { EnvironmentPanel } from "./EnvironmentPanel";

const REFRESH_INTERVAL_MS = 30_000;

const SEVERITY_OPTIONS: Array<{ value: Severity | "all"; label: string; tone: SeverityTone }> = [
  { value: "all", label: "All Severities", tone: "gray" },
  { value: "critical", label: "Critical (RED)", tone: "danger" },
  { value: "warning", label: "Warning (YELLOW)", tone: "warning" },
  { value: "info", label: "Info", tone: "brand" },
  { value: "healthy", label: "Healthy / Info", tone: "success" },
];

function buildServiceOptions(report: HealthReport | null): string[] {
  if (!report) return [];
  const names = new Set<string>();
  for (const svc of report.sections.lag.indexerServices ?? []) {
    names.add(svc.serviceName);
  }
  for (const chk of report.sections.smoke.checks) {
    names.add(chk.name);
    if (chk.category) names.add(chk.category);
  }
  for (const contract of report.sections.registry.expectedContracts) {
    names.add(contract);
  }
  return Array.from(names).sort();
}

function BlockerBar({ blockers }: { blockers: Blocker[] }) {
  if (!blockers || blockers.length === 0) {
    return null;
  }
  return (
    <div className="rounded-lg border border-danger-soft bg-danger-soft/40 p-4 space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium text-danger">
        <ShieldAlert className="h-4 w-4" />
        {blockers.length} blocker{blockers.length === 1 ? "" : "s"} detected
      </div>
      <ul className="space-y-2">
        {blockers.slice(0, 5).map((b) => (
          <li key={b.id} className="text-xs">
            <div className="flex flex-wrap items-start gap-2">
              <SeverityPill
                tone={
                  b.severity === "critical"
                    ? "danger"
                    : b.severity === "warning"
                      ? "warning"
                      : "brand"
                }
                label={`${b.category} / ${b.severity}`}
              />
              <span className="text-foreground font-medium">{b.message}</span>
            </div>
            {b.remediation && (
              <div className="ml-1 mt-1 text-subtle">
                Remediation: {b.remediation}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ReadinessBanner({
  status,
  releaseReady,
  summary,
}: {
  status: OverallStatus;
  releaseReady: boolean;
  summary: HealthReport["summary"];
}) {
  const tone = overallStatusToTone(status);
  const label = overallStatusLabel(status);
  const toneStyles = {
    danger: {
      banner: "bg-danger-soft/60 border-danger-soft",
      icon: <ShieldAlert className="h-6 w-6" />,
      text: "text-danger",
      subtitle:
        "Testnet is NOT ready. Critical blockers must be resolved before release.",
    },
    warning: {
      banner: "bg-warning-soft/60 border-warning-soft",
      icon: <AlertTriangle className="h-6 w-6" />,
      text: "text-warning",
      subtitle:
        "Testnet is degraded — warnings/info present. Can proceed with caution.",
    },
    brand: {
      banner: "bg-brand-soft/60 border-brand-soft",
      icon: <AlertCircle className="h-6 w-6" />,
      text: "text-brand",
      subtitle: "Info signals present.",
    },
    success: {
      banner: "bg-success-soft/60 border-success-soft",
      icon: <ShieldCheck className="h-6 w-6" />,
      text: "text-success",
      subtitle: "All systems operational — testnet is release-ready.",
    },
    gray: {
      banner: "bg-surface border-border",
      icon: <AlertCircle className="h-6 w-6" />,
      text: "text-subtle",
      subtitle: "Awaiting signals...",
    },
  }[tone];

  return (
    <div
      className={`relative overflow-hidden rounded-xl border-2 ${toneStyles.banner} p-5 md:p-6`}
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-4 min-w-0 flex-1">
          <div className={`shrink-0 ${toneStyles.text}`}>
            {toneStyles.icon}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className={`text-xl md:text-2xl font-bold ${toneStyles.text}`}>
                Testnet Status: {label}
              </h2>
              <SeverityPill
                tone={tone}
                label={releaseReady ? "RELEASE OK" : "HOLD RELEASE"}
                icon={releaseReady ? CheckCircle2 : ShieldAlert}
              />
            </div>
            <p className="mt-1.5 text-sm md:text-base text-muted/90 max-w-2xl">
              {toneStyles.subtitle}
            </p>
          </div>
        </div>
        <div className="flex gap-2 items-center shrink-0">
          <div className="flex items-center gap-1.5">
            <SeverityDot tone="danger" />
            <span className="text-xs text-muted">
              {summary.critical} crit
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <SeverityDot tone="warning" />
            <span className="text-xs text-muted">
              {summary.warning} warn
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <SeverityDot tone="brand" />
            <span className="text-xs text-muted">{summary.info} info</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function TestnetHealthConsole() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const deploymentInfo = useMemo(() => getDeploymentInfo(), []);

  const [report, setReport] = useState<HealthReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [severityFilter, setSeverityFilter] = useState<
    Severity | "all"
  >("all");
  const [serviceFilter, setServiceFilter] = useState<string>("all");

  const severitySet = useMemo(() => {
    if (severityFilter === "all") return new Set<string>();
    return new Set<string>([severityFilter]);
  }, [severityFilter]);

  const serviceSet = useMemo(() => {
    if (!serviceFilter || serviceFilter === "all") return new Set<string>();
    return new Set<string>([serviceFilter.toLowerCase()]);
  }, [serviceFilter]);

  const serviceOptions = useMemo(
    () => buildServiceOptions(report),
    [report],
  );

  const loadReport = useCallback(async () => {
    try {
      setRefreshing(true);
      const res = await fetch(
        `${apiBase}/admin/rc-validation/report`,
        {
          cache: "no-store",
          headers: { Accept: "application/json" },
        },
      );

      if (!res.ok) {
        if (res.status === 401 || res.status === 403) {
          throw new Error(
            `Admin access required (HTTP ${res.status}). Add a valid admin API key.`,
          );
        }
        if (res.status === 404) {
          throw new Error(
            `Admin health endpoint not found (HTTP 404). Ensure the backend serves /admin/rc-validation/report.`,
          );
        }
        throw new Error(
          `Failed to load health report (HTTP ${res.status}).`,
        );
      }

      const payload = (await res.json()) as HealthReport;

      // Defensive validation — coerce malformed payloads so UI never crashes.
      const safe: HealthReport = {
        reportId:
          typeof payload?.reportId === "string" ? payload.reportId : "n/a",
        generatedAt:
          typeof payload?.generatedAt === "string"
            ? payload.generatedAt
            : new Date().toISOString(),
        network:
          typeof payload?.network === "string"
            ? payload.network
            : deploymentInfo.network,
        environment:
          typeof payload?.environment === "string"
            ? payload.environment
            : deploymentInfo.vercelEnv ?? deploymentInfo.network,
        releaseReady: !!payload?.releaseReady,
        overallStatus:
          payload?.overallStatus === "ready" ||
          payload?.overallStatus === "degraded" ||
          payload?.overallStatus === "blocked"
            ? payload.overallStatus
            : "degraded",
        sections: {
          smoke: {
            status:
              payload?.sections?.smoke?.status ?? "unknown",
            ready: !!payload?.sections?.smoke?.ready,
            checks: Array.isArray(payload?.sections?.smoke?.checks)
              ? payload.sections.smoke.checks.map((c) => ({ ...c }))
              : [],
            passed: Number(payload?.sections?.smoke?.passed ?? 0) || 0,
            failed: Number(payload?.sections?.smoke?.failed ?? 0) || 0,
            skipped:
              payload?.sections?.smoke?.skipped !== undefined
                ? Number(payload.sections.smoke.skipped) || 0
                : undefined,
            totalDurationMs:
              payload?.sections?.smoke?.totalDurationMs !== undefined
                ? Number(payload.sections.smoke.totalDurationMs) || 0
                : undefined,
            lastRunAt:
              typeof payload?.sections?.smoke?.lastRunAt === "string"
                ? payload.sections.smoke.lastRunAt
                : undefined,
            failureDetails: Array.isArray(
              payload?.sections?.smoke?.failureDetails,
            )
              ? (payload.sections.smoke.failureDetails as string[])
              : undefined,
          },
          registry: {
            status: payload?.sections?.registry?.status ?? "unknown",
            network:
              typeof payload?.sections?.registry?.network === "string"
                ? payload.sections.registry.network
                : deploymentInfo.network,
            authoritative: !!payload?.sections?.registry?.authoritative,
            version:
              Number(payload?.sections?.registry?.version) || 0,
            activeContracts:
              Number(payload?.sections?.registry?.activeContracts) || 0,
            expectedContracts: Array.isArray(
              payload?.sections?.registry?.expectedContracts,
            )
              ? (payload.sections.registry.expectedContracts as string[])
              : [],
            missingContracts: Array.isArray(
              payload?.sections?.registry?.missingContracts,
            )
              ? (payload.sections.registry.missingContracts as string[])
              : [],
            contractDetails: Array.isArray(
              payload?.sections?.registry?.contractDetails,
            )
              ? (payload.sections.registry.contractDetails as HealthReport["sections"]["registry"]["contractDetails"])
              : undefined,
            mismatchedContracts:
              payload?.sections?.registry?.mismatchedContracts !==
              undefined
                ? Number(
                    payload.sections.registry.mismatchedContracts,
                  ) || 0
                : undefined,
          },
          lag: {
            status: payload?.sections?.lag?.status ?? "unknown",
            currentNetworkLedger:
              payload?.sections?.lag?.currentNetworkLedger ===
              null ||
              typeof payload?.sections?.lag?.currentNetworkLedger ===
                "number"
                ? payload.sections.lag.currentNetworkLedger
                : null,
            lastIndexedLedger:
              payload?.sections?.lag?.lastIndexedLedger ===
              null ||
              typeof payload?.sections?.lag?.lastIndexedLedger ===
                "number"
                ? payload.sections.lag.lastIndexedLedger
                : null,
            lagLedgers:
              payload?.sections?.lag?.lagLedgers === null ||
              typeof payload?.sections?.lag?.lagLedgers === "number"
                ? payload.sections.lag.lagLedgers
                : null,
            lagSeconds:
              payload?.sections?.lag?.lagSeconds === undefined
                ? undefined
                : Number(payload.sections.lag.lagSeconds) || 0,
            isLagging: !!payload?.sections?.lag?.isLagging,
            isBlocking: !!payload?.sections?.lag?.isBlocking,
            thresholdLedgers:
              Number(payload?.sections?.lag?.thresholdLedgers) || 0,
            indexerServices: Array.isArray(
              payload?.sections?.lag?.indexerServices,
            )
              ? (payload.sections.lag.indexerServices as HealthReport["sections"]["lag"]["indexerServices"])
              : undefined,
          },
          environment: {
            status:
              payload?.sections?.environment?.status ?? "unknown",
            checks: Array.isArray(payload?.sections?.environment?.checks)
              ? (payload.sections.environment.checks as HealthReport["sections"]["environment"]["checks"])
              : [],
            passed:
              Number(payload?.sections?.environment?.passed) || 0,
            failed:
              Number(payload?.sections?.environment?.failed) || 0,
            warnings:
              Number(payload?.sections?.environment?.warnings) || 0,
            metadata:
              payload?.sections?.environment?.metadata &&
              typeof payload.sections.environment.metadata === "object"
                ? (payload.sections.environment.metadata as HealthReport["sections"]["environment"]["metadata"])
                : undefined,
          },
        },
        blockers: Array.isArray(payload?.blockers)
          ? (payload.blockers as Blocker[])
          : [],
        summary: {
          critical: Number(payload?.summary?.critical) || 0,
          warning: Number(payload?.summary?.warning) || 0,
          info: Number(payload?.summary?.info) || 0,
        },
      };

      setReport(safe);
      setError(null);
    } catch (err) {
      const msg =
        err instanceof Error && err.message
          ? err.message
          : "Unknown error loading health report.";
      setError(msg);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [apiBase, deploymentInfo.network, deploymentInfo.vercelEnv]);

  useEffect(() => {
    void loadReport();
    const id = window.setInterval(() => {
      void loadReport();
    }, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [loadReport]);

  if (loading && !report) {
    return <LoadingSkeleton label="Loading testnet health report..." />;
  }

  if (error && !report) {
    return (
      <ErrorState
        title="Unable to load testnet health report"
        message={error}
        onRetry={() => {
          void loadReport();
        }}
      />
    );
  }

  if (!report) {
    return (
      <ErrorState
        title="No health report available"
        onRetry={() => {
          void loadReport();
        }}
      />
    );
  }

  const criticalBlockers = report.blockers.filter(
    (b) => b.severity === "critical",
  );

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto">
      {/* Header + meta */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <h1 className="text-2xl md:text-3xl font-bold text-foreground">
              Testnet Health Console
            </h1>
            <span className="text-xs font-medium uppercase tracking-wide bg-brand-soft text-brand rounded-full px-2.5 py-1 border border-brand-soft">
              Admin
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-subtle">
            <span>
              Report <span className="font-mono">{report.reportId.slice(0, 8)}</span>
            </span>
            <span>Generated {formatDateTime(report.generatedAt)}</span>
            <span>
              {report.network} · {report.environment}
            </span>
            <span>
              Refresh: every {Math.round(REFRESH_INTERVAL_MS / 1000)}s
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => {
              void loadReport();
            }}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-2 text-sm font-medium text-foreground hover:bg-surface disabled:opacity-60"
            aria-label="Refresh health report"
          >
            <RefreshCw
              className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
            />
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {/* Readiness */}
      <ReadinessBanner
        status={report.overallStatus}
        releaseReady={report.releaseReady}
        summary={report.summary}
      />

      {/* Top-level summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard
          title="Registry"
          value={report.sections.registry.status === "pass" ? "OK" : report.sections.registry.status === "fail" ? "FAIL" : "WARN"}
          subtitle={`${report.sections.registry.activeContracts} active · v${report.sections.registry.version}`}
          tone={overallStatusToTone(
            report.sections.registry.status === "pass"
              ? "ready"
              : report.sections.registry.status === "fail"
                ? "blocked"
                : "degraded",
          )}
          icon={ShieldCheck}
        />
        <SummaryCard
          title="Indexer Lag"
          value={
            report.sections.lag.isBlocking
              ? "BLOCKED"
              : report.sections.lag.isLagging
                ? "LAGGING"
                : "SYNCED"
          }
          subtitle={
            report.sections.lag.lagLedgers === null
              ? "no ledger data"
              : `${report.sections.lag.lagLedgers} ledgers behind`
          }
          tone={
            report.sections.lag.isBlocking
              ? "danger"
              : report.sections.lag.isLagging
                ? "warning"
                : "success"
          }
          icon={AlertTriangle}
        />
        <SummaryCard
          title="Smoke Tests"
          value={`${report.sections.smoke.passed}/${report.sections.smoke.passed + report.sections.smoke.failed}`}
          subtitle={`${report.sections.smoke.failed} failed · ${(report.sections.smoke.totalDurationMs ?? 0) / 1000}s`}
          tone={
            report.sections.smoke.failed > 0
              ? "danger"
              : report.sections.smoke.status === "warning"
                ? "warning"
                : "success"
          }
          icon={CheckCircle2}
        />
        <SummaryCard
          title="Env Parity"
          value={`${report.sections.environment.passed}/${report.sections.environment.passed + report.sections.environment.failed + report.sections.environment.warnings}`}
          subtitle={`${report.sections.environment.warnings} warnings`}
          tone={
            report.sections.environment.failed > 0
              ? "danger"
              : report.sections.environment.warnings > 0
                ? "warning"
                : "success"
          }
          icon={AlertCircle}
        />
      </div>

      {/* Critical blockers condensed view */}
      {criticalBlockers.length > 0 && (
        <BlockerBar blockers={criticalBlockers} />
      )}

      {/* Filters */}
      <div className="rounded-lg border border-border bg-card p-4 flex flex-wrap items-center gap-4">
        <div className="inline-flex items-center gap-2 text-sm font-medium text-muted">
          <Filter className="h-4 w-4 text-subtle" />
          Filters
        </div>
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-0">
          <div className="flex items-center gap-2 min-w-[240px] flex-1 max-w-md">
            <label
              htmlFor="hc-severity"
              className="text-xs font-medium text-subtle shrink-0"
            >
              Severity
            </label>
            <select
              id="hc-severity"
              value={severityFilter}
              onChange={(e) =>
                setSeverityFilter(e.target.value as Severity | "all")
              }
              className="w-full min-w-0 flex-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand"
            >
              {SEVERITY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2 min-w-[240px] flex-1 max-w-md">
            <label
              htmlFor="hc-service"
              className="text-xs font-medium text-subtle shrink-0"
            >
              Service
            </label>
            <select
              id="hc-service"
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="w-full min-w-0 flex-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand"
            >
              <option value="all">All Services</option>
              {serviceOptions.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>
        {(severityFilter !== "all" || serviceFilter !== "all") && (
          <button
            type="button"
            onClick={() => {
              setSeverityFilter("all");
              setServiceFilter("all");
            }}
            className="text-xs font-medium text-brand hover:underline"
          >
            Clear
          </button>
        )}
      </div>

      {/* 4 core panels */}
      <div className="space-y-5">
        <RegistryPanel
          data={report.sections.registry}
          severityFilter={severitySet}
        />
        <IndexerLagPanel
          data={report.sections.lag}
          serviceFilter={serviceSet}
          severityFilter={severitySet}
        />
        <SmokeTestPanel
          data={report.sections.smoke}
          serviceFilter={serviceSet}
          severityFilter={severitySet}
        />
        <EnvironmentPanel
          data={report.sections.environment}
          severityFilter={severitySet}
        />
      </div>

      {error && (
        <div className="rounded-md border border-warning-soft bg-warning-soft/40 px-3 py-2 text-xs text-warning">
          Recent non-fatal fetch issue: {error} — stale report is displayed.
        </div>
      )}
    </div>
  );
}
