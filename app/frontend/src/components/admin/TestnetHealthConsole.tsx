"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Boxes,
  CheckCircle2,
  CircleAlert,
  Clock3,
  RefreshCw,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";

type Severity = "critical" | "warning" | "info";
type Category = "smoke" | "registry" | "lag" | "environment";
type SectionStatus = "pass" | "warning" | "fail" | "unknown";
type OverallStatus = "ready" | "degraded" | "blocked";

type Blocker = {
  id: string;
  severity: Severity;
  category: Category;
  message: string;
  remediation?: string;
  detectedAt: string;
};

type SmokeCheck = {
  name: string;
  status: "up" | "degraded" | "down";
  error?: string;
};

type EnvironmentCheck = {
  check: string;
  status: "pass" | "fail" | "warning";
  details?: string;
};

type HealthReport = {
  reportId: string;
  generatedAt: string;
  network: string;
  environment: string;
  releaseReady: boolean;
  overallStatus: OverallStatus;
  sections: {
    smoke: {
      status: SectionStatus;
      ready: boolean;
      checks: SmokeCheck[];
      passed: number;
      failed: number;
    };
    registry: {
      status: SectionStatus;
      network: string;
      authoritative: boolean;
      version: number;
      activeContracts: number;
      expectedContracts: string[];
      missingContracts: string[];
    };
    lag: {
      status: SectionStatus;
      currentNetworkLedger: number | null;
      lastIndexedLedger: number | null;
      lagLedgers: number | null;
      isLagging: boolean;
      isBlocking: boolean;
      thresholdLedgers: number;
    };
    environment: {
      status: SectionStatus;
      checks: EnvironmentCheck[];
      passed: number;
      failed: number;
      warnings: number;
    };
  };
  blockers: Blocker[];
  summary: Record<Severity, number>;
};

const REFRESH_MS = 30_000;

const severityClasses: Record<Severity | "healthy", string> = {
  critical: "border-danger-soft bg-danger-soft text-danger",
  warning: "border-warning-soft bg-warning-soft text-warning",
  info: "border-brand-soft bg-brand-soft text-brand",
  healthy: "border-success-soft bg-success-soft text-success",
};

function severityForSection(status: SectionStatus): Severity | "healthy" {
  if (status === "fail") return "critical";
  if (status === "warning" || status === "unknown") return "warning";
  return "healthy";
}

function severityForSmoke(check: SmokeCheck): Severity {
  if (check.status === "down") return "critical";
  if (check.status === "degraded") return "warning";
  return "info";
}

function severityForEnvironment(check: EnvironmentCheck): Severity {
  if (check.status === "fail") return "warning";
  return "info";
}

function formatDateTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(date);
}

function SeverityBadge({ severity }: { severity: Severity | "healthy" }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${severityClasses[severity]}`}
    >
      {severity}
    </span>
  );
}

function Panel({
  id,
  title,
  description,
  status,
  children,
}: {
  id: string;
  title: string;
  description: string;
  status: SectionStatus;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="overflow-hidden rounded-xl border border-border bg-card">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div>
          <h3 className="text-base font-semibold text-foreground">{title}</h3>
          <p className="mt-1 text-sm text-subtle">{description}</p>
        </div>
        <SeverityBadge severity={severityForSection(status)} />
      </div>
      {children}
    </section>
  );
}

function Metric({
  label,
  value,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-subtle">{label}</p>
      <p className="mt-1 text-xl font-semibold text-foreground">{value}</p>
      {hint ? <p className="mt-1 text-xs text-faint">{hint}</p> : null}
    </div>
  );
}

function EmptyRows({ message }: { message: string }) {
  return (
    <div className="px-5 py-8 text-center text-sm text-subtle">{message}</div>
  );
}

function OperationalLink({ href, children }: { href: string; children: React.ReactNode }) {
  const external = href.startsWith("http");
  const classes =
    "inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-surface";

  if (external) {
    return (
      <a href={href} target="_blank" rel="noreferrer" className={classes}>
        {children}
        <ArrowUpRight className="h-3.5 w-3.5" />
      </a>
    );
  }

  return (
    <Link href={href} className={classes}>
      {children}
      <ArrowUpRight className="h-3.5 w-3.5" />
    </Link>
  );
}

export function TestnetHealthConsole() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const registryUrl = `${apiBase}/contracts/registry`;
  const inFlight = useRef(false);

  const [report, setReport] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [category, setCategory] = useState<Category | "all">("all");

  const loadReport = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);

    try {
      const response = await fetch(`${apiBase}/admin/rc-validation/report`, {
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "x-api-key": process.env.NEXT_PUBLIC_ADMIN_API_KEY ?? "",
        },
      });

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error(
            `Admin health API rejected the request (${response.status}). Check NEXT_PUBLIC_ADMIN_API_KEY.`,
          );
        }
        throw new Error(`Health report request failed (${response.status}).`);
      }

      const payload = (await response.json()) as HealthReport;
      if (!payload?.sections || !payload?.summary || !Array.isArray(payload?.blockers)) {
        throw new Error("Health report returned an unexpected payload.");
      }

      setReport(payload);
      setError(null);
    } catch (loadError) {
      setError(
        loadError instanceof Error
          ? loadError.message
          : "Unable to load testnet health report.",
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
      inFlight.current = false;
    }
  }, [apiBase]);

  useEffect(() => {
    void loadReport();
    const interval = window.setInterval(() => void loadReport(), REFRESH_MS);
    return () => window.clearInterval(interval);
  }, [loadReport]);

  const filteredBlockers = useMemo(() => {
    if (!report) return [];
    return report.blockers.filter(
      (item) =>
        (severity === "all" || item.severity === severity) &&
        (category === "all" || item.category === category),
    );
  }, [category, report, severity]);

  const showCategory = (value: Category) => category === "all" || category === value;
  const matchesSeverity = (value: Severity) => severity === "all" || severity === value;

  if (loading && !report) {
    return (
      <section className="rounded-xl border border-border bg-card p-6" aria-live="polite">
        <div className="flex items-center gap-3 text-subtle">
          <RefreshCw className="h-5 w-5 animate-spin" />
          Loading testnet readiness signals…
        </div>
      </section>
    );
  }

  if (!report) {
    return (
      <section className="rounded-xl border border-danger-soft bg-danger-soft p-6" role="alert">
        <div className="flex items-start gap-3">
          <CircleAlert className="mt-0.5 h-5 w-5 shrink-0 text-danger" />
          <div>
            <h2 className="font-semibold text-danger">Testnet health is unavailable</h2>
            <p className="mt-1 text-sm text-muted">{error ?? "No report was returned."}</p>
            <button
              type="button"
              onClick={() => void loadReport()}
              className="mt-4 inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm font-medium text-foreground hover:bg-surface"
            >
              <RefreshCw className="h-4 w-4" /> Retry
            </button>
          </div>
        </div>
      </section>
    );
  }

  const statusTone =
    report.overallStatus === "blocked"
      ? "critical"
      : report.overallStatus === "degraded"
        ? "warning"
        : "healthy";

  const smokeRows = report.sections.smoke.checks.filter((check) =>
    matchesSeverity(severityForSmoke(check)),
  );
  const registryRows = report.sections.registry.expectedContracts.filter((name) => {
    const rowSeverity: Severity = report.sections.registry.missingContracts.includes(name)
      ? "critical"
      : "info";
    return matchesSeverity(rowSeverity);
  });
  const environmentRows = report.sections.environment.checks.filter((check) =>
    matchesSeverity(severityForEnvironment(check)),
  );

  const lagSeverity: Severity = report.sections.lag.isBlocking
    ? "critical"
    : report.sections.lag.isLagging || report.sections.lag.status === "unknown"
      ? "warning"
      : "info";

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-border bg-card p-5 md:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-bold text-foreground">Testnet Health Console</h1>
              <SeverityBadge severity={statusTone} />
            </div>
            <p className="mt-2 max-w-3xl text-sm text-subtle">
              One view for release readiness, contract registry status, indexer lag,
              smoke checks, and environment parity.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void loadReport()}
            disabled={refreshing}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-2 text-sm font-medium text-foreground hover:bg-surface-strong disabled:opacity-60"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Metric
            label="Readiness"
            value={report.releaseReady ? "Release ready" : "Hold release"}
            hint={`${report.summary.critical} critical · ${report.summary.warning} warning · ${report.summary.info} info`}
          />
          <Metric
            label="Network"
            value={report.network}
            hint={`Environment: ${report.environment}`}
          />
          <Metric
            label="Report"
            value={report.reportId.slice(0, 8)}
            hint={formatDateTime(report.generatedAt)}
          />
          <Metric
            label="Auto refresh"
            value={`${REFRESH_MS / 1000}s`}
            hint="Last successful report stays visible if refresh fails"
          />
        </div>

        <div className="mt-5 flex flex-wrap gap-2" aria-label="Operational links">
          <OperationalLink href="/dashboard">Transactions</OperationalLink>
          <OperationalLink href="/webhooks">Webhook logs</OperationalLink>
          <OperationalLink href={registryUrl}>Registry entries</OperationalLink>
          <OperationalLink href="/settings">Environment settings</OperationalLink>
        </div>
      </section>

      {error ? (
        <div className="flex items-start gap-2 rounded-lg border border-warning-soft bg-warning-soft px-4 py-3 text-sm text-warning" role="status">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          Refresh failed: {error} The last successful report is still displayed.
        </div>
      ) : null}

      <section className="rounded-xl border border-border bg-card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <label htmlFor="health-severity" className="text-xs font-semibold uppercase tracking-wide text-subtle">
              Severity
            </label>
            <select
              id="health-severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value as Severity | "all")}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
            >
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label htmlFor="health-category" className="text-xs font-semibold uppercase tracking-wide text-subtle">
              Signal
            </label>
            <select
              id="health-category"
              value={category}
              onChange={(event) => setCategory(event.target.value as Category | "all")}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
            >
              <option value="all">All</option>
              <option value="registry">Registry</option>
              <option value="lag">Indexer lag</option>
              <option value="smoke">Smoke tests</option>
              <option value="environment">Environment</option>
            </select>
          </div>
          {(severity !== "all" || category !== "all") ? (
            <button
              type="button"
              onClick={() => {
                setSeverity("all");
                setCategory("all");
              }}
              className="text-sm font-medium text-brand hover:underline"
            >
              Clear filters
            </button>
          ) : null}
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-border bg-card">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-foreground">Actionable readiness signals</h2>
            <p className="mt-1 text-sm text-subtle">Blockers and advisories returned by the release-candidate API.</p>
          </div>
          <span className="text-xs text-faint">{filteredBlockers.length} shown</span>
        </div>
        {filteredBlockers.length === 0 ? (
          <EmptyRows message="No blockers match the current filters." />
        ) : (
          <div className="divide-y divide-border">
            {filteredBlockers.map((blocker) => (
              <div key={blocker.id} className="grid gap-3 px-5 py-4 md:grid-cols-[140px_1fr]">
                <div className="flex items-start gap-2">
                  <SeverityBadge severity={blocker.severity} />
                  <span className="text-xs capitalize text-faint">{blocker.category}</span>
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">{blocker.message}</p>
                  {blocker.remediation ? (
                    <p className="mt-1 text-sm text-subtle">
                      <span className="font-medium">Action:</span> {blocker.remediation}
                    </p>
                  ) : null}
                  <p className="mt-1 text-xs text-faint">Detected {formatDateTime(blocker.detectedAt)}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        {showCategory("registry") ? (
          <Panel
            id="registry-health"
            title="Contract registry"
            description="Expected deployments compared with the authoritative registry."
            status={report.sections.registry.status}
          >
            <div className="grid grid-cols-2 gap-3 border-b border-border p-5 sm:grid-cols-4">
              <Metric label="Version" value={`v${report.sections.registry.version}`} />
              <Metric label="Active" value={report.sections.registry.activeContracts} />
              <Metric label="Expected" value={report.sections.registry.expectedContracts.length} />
              <Metric
                label="Source"
                value={report.sections.registry.authoritative ? "Authoritative" : "Fallback"}
              />
            </div>
            {registryRows.length === 0 ? (
              <EmptyRows message="No registry entries match the severity filter." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface text-xs uppercase tracking-wide text-subtle">
                    <tr>
                      <th className="px-5 py-3 font-medium">Contract</th>
                      <th className="px-5 py-3 font-medium">State</th>
                      <th className="px-5 py-3 font-medium">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {registryRows.map((name) => {
                      const missing = report.sections.registry.missingContracts.includes(name);
                      return (
                        <tr key={name}>
                          <td className="px-5 py-3 font-mono text-foreground">{name}</td>
                          <td className="px-5 py-3 text-subtle">{missing ? "Missing" : "Active"}</td>
                          <td className="px-5 py-3">
                            <SeverityBadge severity={missing ? "critical" : "info"} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        ) : null}

        {showCategory("lag") ? (
          <Panel
            id="indexer-health"
            title="Indexer lag"
            description="Network head and last indexed checkpoint with the active guard threshold."
            status={report.sections.lag.status}
          >
            {matchesSeverity(lagSeverity) ? (
              <div className="grid grid-cols-2 gap-3 p-5 sm:grid-cols-4">
                <Metric
                  label="Lag"
                  value={report.sections.lag.lagLedgers ?? "Unknown"}
                  hint="ledgers"
                />
                <Metric
                  label="Threshold"
                  value={report.sections.lag.thresholdLedgers}
                  hint="ledgers"
                />
                <Metric
                  label="Network head"
                  value={report.sections.lag.currentNetworkLedger ?? "Unknown"}
                />
                <Metric
                  label="Indexed"
                  value={report.sections.lag.lastIndexedLedger ?? "Unknown"}
                  hint={report.sections.lag.isBlocking ? "Traffic guard blocking" : "Guard not blocking"}
                />
              </div>
            ) : (
              <EmptyRows message="Indexer lag does not match the severity filter." />
            )}
          </Panel>
        ) : null}

        {showCategory("smoke") ? (
          <Panel
            id="smoke-health"
            title="Smoke test status"
            description="Deep readiness probes for dependencies required by the testnet release."
            status={report.sections.smoke.status}
          >
            <div className="flex flex-wrap gap-3 border-b border-border p-5">
              <Metric label="Passed" value={report.sections.smoke.passed} />
              <Metric label="Failed" value={report.sections.smoke.failed} />
              <Metric label="Ready" value={report.sections.smoke.ready ? "Yes" : "No"} />
            </div>
            {smokeRows.length === 0 ? (
              <EmptyRows message="No smoke checks match the severity filter." />
            ) : (
              <div className="divide-y divide-border">
                {smokeRows.map((check) => (
                  <div key={check.name} className="flex flex-wrap items-start justify-between gap-3 px-5 py-3">
                    <div>
                      <p className="text-sm font-medium text-foreground">{check.name}</p>
                      {check.error ? <p className="mt-1 text-xs text-danger">{check.error}</p> : null}
                    </div>
                    <SeverityBadge severity={severityForSmoke(check)} />
                  </div>
                ))}
              </div>
            )}
          </Panel>
        ) : null}

        {showCategory("environment") ? (
          <Panel
            id="environment-health"
            title="Environment & deployment"
            description="Parity checks plus report metadata for the active testnet deployment."
            status={report.sections.environment.status}
          >
            <div className="grid grid-cols-2 gap-3 border-b border-border p-5 sm:grid-cols-4">
              <Metric label="Environment" value={report.environment} />
              <Metric label="Network" value={report.network} />
              <Metric label="Registry" value={`v${report.sections.registry.version}`} />
              <Metric label="Report ID" value={report.reportId.slice(0, 8)} />
            </div>
            {environmentRows.length === 0 ? (
              <EmptyRows message="No environment checks match the severity filter." />
            ) : (
              <div className="divide-y divide-border">
                {environmentRows.map((check) => (
                  <div key={check.check} className="flex flex-wrap items-start justify-between gap-3 px-5 py-3">
                    <div>
                      <p className="text-sm font-medium text-foreground">{check.check}</p>
                      {check.details ? <p className="mt-1 text-xs text-subtle">{check.details}</p> : null}
                    </div>
                    <SeverityBadge severity={severityForEnvironment(check)} />
                  </div>
                ))}
              </div>
            )}
          </Panel>
        ) : null}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-4">
          <Boxes className="h-5 w-5 text-brand" />
          <span className="text-sm text-muted">Registry deployment state</span>
        </div>
        <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-4">
          <Activity className="h-5 w-5 text-success" />
          <span className="text-sm text-muted">Indexer checkpoint health</span>
        </div>
        <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-4">
          {report.sections.smoke.ready ? (
            <CheckCircle2 className="h-5 w-5 text-success" />
          ) : (
            <ShieldAlert className="h-5 w-5 text-danger" />
          )}
          <span className="text-sm text-muted">Smoke readiness probes</span>
        </div>
        <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-4">
          {report.releaseReady ? (
            <ShieldCheck className="h-5 w-5 text-success" />
          ) : (
            <ServerCog className="h-5 w-5 text-warning" />
          )}
          <span className="text-sm text-muted">Deployment parity</span>
        </div>
      </div>

      <p className="flex items-center gap-2 text-xs text-faint">
        <Clock3 className="h-3.5 w-3.5" />
        Data source: /admin/rc-validation/report · generated {formatDateTime(report.generatedAt)}
      </p>
    </div>
  );
}
