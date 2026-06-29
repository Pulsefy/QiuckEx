"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  ChevronRight,
  DatabaseZap,
  Filter,
  RadioTower,
  ShieldCheck,
  Workflow,
} from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";
import { getSectionTone, getSeverityTone, summarizeReport } from "./testnetHealth.utils";

type Severity = "critical" | "warning" | "info";
type SectionStatus = "pass" | "warning" | "fail" | "unknown";

type SmokeCheck = {
  name: string;
  status: "up" | "down";
  error?: string;
};

type RegistrySection = {
  status: SectionStatus;
  network: string;
  authoritative: boolean;
  version: number;
  activeContracts: number;
  expectedContracts: string[];
  missingContracts: string[];
};

type LagSection = {
  status: SectionStatus;
  currentNetworkLedger: number | null;
  lastIndexedLedger: number | null;
  lagLedgers: number | null;
  isLagging: boolean;
  isBlocking: boolean;
  thresholdLedgers: number;
};

type EnvironmentCheck = {
  check: string;
  status: "pass" | "fail" | "warning";
  details?: string;
};

type EnvironmentSection = {
  status: SectionStatus;
  checks: EnvironmentCheck[];
  passed: number;
  failed: number;
  warnings: number;
};

type Blocker = {
  id: string;
  severity: Severity;
  category: string;
  message: string;
  remediation?: string;
  detectedAt: string;
};

type Report = {
  reportId: string;
  generatedAt: string;
  network: string;
  environment: string;
  releaseReady: boolean;
  overallStatus: "ready" | "degraded" | "blocked";
  summary: {
    critical: number;
    warning: number;
    info: number;
  };
  sections: {
    smoke: {
      status: SectionStatus;
      ready: boolean;
      checks: SmokeCheck[];
      passed: number;
      failed: number;
    };
    registry: RegistrySection;
    lag: LagSection;
    environment: EnvironmentSection;
  };
  blockers: Blocker[];
};

const severityFilterOptions = ["all", "critical", "warning", "info"] as const;

type SeverityFilter = (typeof severityFilterOptions)[number];

export function TestnetHealthConsole() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await fetch(`${apiBase}/admin/rc-validation/report`, {
          cache: "no-store",
        });
        if (!response.ok) {
          throw new Error(`Report failed (${response.status})`);
        }
        const payload = (await response.json()) as Report;
        if (!cancelled) {
          setReport(payload);
        }
      } catch (fetchError) {
        if (!cancelled) {
          setError(fetchError instanceof Error ? fetchError.message : "Unable to load report.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    const intervalId = window.setInterval(() => {
      void load();
    }, 60000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [apiBase]);

  const summary = summarizeReport(report ?? {});
  const filteredBlockers = useMemo(() => {
    if (!report) return [];
    return report.blockers.filter(
      (blocker: Blocker) => severityFilter === "all" || blocker.severity === severityFilter,
    );
  }, [report, severityFilter]);

  const cards = [
    {
      title: "Smoke status",
      value: report?.sections.smoke.ready ? "Ready" : "Needs attention",
      detail: `${report?.sections.smoke.passed ?? 0} passed • ${report?.sections.smoke.failed ?? 0} failed`,
      tone: report?.sections.smoke.status === "fail" ? "danger" : report?.sections.smoke.status === "warning" ? "warning" : "success",
      icon: ShieldCheck,
    },
    {
      title: "Registry",
      value: report?.sections.registry.authoritative ? "Authoritative" : "Needs review",
      detail: `${report?.sections.registry.activeContracts ?? 0} active contracts • ${report?.sections.registry.missingContracts.length ?? 0} missing`,
      tone: report?.sections.registry.status === "fail" ? "danger" : report?.sections.registry.status === "warning" ? "warning" : "success",
      icon: DatabaseZap,
    },
    {
      title: "Indexer lag",
      value: report?.sections.lag.isBlocking ? "Blocking" : report?.sections.lag.isLagging ? "Lagging" : "Healthy",
      detail: `${report?.sections.lag.lagLedgers ?? 0} ledgers behind`,
      tone: report?.sections.lag.status === "fail" ? "danger" : report?.sections.lag.status === "warning" ? "warning" : "success",
      icon: RadioTower,
    },
    {
      title: "Environment",
      value: report?.sections.environment.status === "pass" ? "Aligned" : report?.sections.environment.status === "warning" ? "Needs review" : "Attention",
      detail: `${report?.sections.environment.warnings ?? 0} warnings • ${report?.sections.environment.failed ?? 0} failed`,
      tone: report?.sections.environment.status === "fail" ? "danger" : report?.sections.environment.status === "warning" ? "warning" : "success",
      icon: Workflow,
    },
  ];

  const sectionRows = [
    {
      title: "Smoke probes",
      status: report?.sections.smoke.status ?? "unknown",
      detail: `${report?.sections.smoke.checks.length ?? 0} checks`,
    },
    {
      title: "Registry",
      status: report?.sections.registry.status ?? "unknown",
      detail: `${report?.sections.registry.activeContracts ?? 0}/${report?.sections.registry.expectedContracts.length ?? 0} expected`,
    },
    {
      title: "Indexer lag",
      status: report?.sections.lag.status ?? "unknown",
      detail: `${report?.sections.lag.lagLedgers ?? 0} ledgers behind`,
    },
    {
      title: "Environment",
      status: report?.sections.environment.status ?? "unknown",
      detail: `${report?.sections.environment.passed ?? 0} passed • ${report?.sections.environment.warnings ?? 0} warnings`,
    },
  ];

  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-sm">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.24em] text-brand">Testnet health</p>
          <h2 className="mt-1 text-2xl font-semibold text-foreground">Admin readiness console</h2>
          <p className="mt-2 max-w-2xl text-sm text-subtle">
            One place to assess release-readiness, registry health, indexer lag, smoke status, and deployment metadata before shipping.
          </p>
        </div>
        <div className="rounded-xl border border-border bg-surface px-4 py-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-subtle">Overall</div>
          <div className={`mt-1 inline-flex items-center rounded-full border px-3 py-1 text-sm font-semibold ${report ? getSectionTone(report.sections.smoke.status) : "border-slate-200 bg-slate-50 text-slate-600"}`}>
            {loading ? "Loading…" : summary.overall}
          </div>
          <div className="mt-2 text-sm text-subtle">{summary.blocks} active signals</div>
        </div>
      </div>

      {error && (
        <div className="mt-5 rounded-lg border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning">
          {error}
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => {
          const Icon = card.icon;
          const toneClass = card.tone === "danger" ? "border-danger/40 bg-danger/10 text-danger" : card.tone === "warning" ? "border-warning/40 bg-warning/10 text-warning" : "border-success/40 bg-success/10 text-success";
          return (
            <div key={card.title} className={`rounded-xl border p-4 ${toneClass}`}>
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold">{card.title}</div>
                <Icon className="h-4 w-4" />
              </div>
              <div className="mt-3 text-lg font-semibold">{card.value}</div>
              <div className="mt-1 text-sm opacity-80">{card.detail}</div>
            </div>
          );
        })}
      </div>

      <div className="mt-6 overflow-hidden rounded-xl border border-border">
        <div className="border-b border-border bg-surface/70 px-4 py-3">
          <h3 className="text-base font-semibold text-foreground">Section health</h3>
          <p className="text-sm text-subtle">Current lifecycle status for smoke, registry, lag, and environment checks.</p>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-border text-sm">
            <thead className="bg-surface/60 text-left text-xs uppercase tracking-[0.2em] text-subtle">
              <tr>
                <th className="px-4 py-3">Section</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border bg-card">
              {sectionRows.map((row) => (
                <tr key={row.title}>
                  <td className="px-4 py-3 font-medium text-foreground">{row.title}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] ${getSectionTone(row.status as SectionStatus)}`}>
                      {row.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-subtle">{row.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[1.35fr_0.95fr]">
        <div className="rounded-xl border border-border bg-surface/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-foreground">Severity queue</h3>
              <p className="text-sm text-subtle">Actionable blockers and warnings from the latest backend report.</p>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-border bg-white px-3 py-2 text-sm text-subtle">
              <Filter className="h-4 w-4" />
              <select className="bg-transparent outline-none" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}>
                {severityFilterOptions.map((option) => (
                  <option key={option} value={option}>
                    {option === "all" ? "All severities" : option}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-4 space-y-3">
            {filteredBlockers.length === 0 && (
              <div className="rounded-lg border border-dashed border-border p-4 text-sm text-subtle">
                No blocker events match this filter.
              </div>
            )}
            {filteredBlockers.map((blocker) => (
              <div key={blocker.id} className={`rounded-lg border p-4 ${getSeverityTone(blocker.severity)}`}>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold">{blocker.message}</div>
                    <div className="mt-1 text-xs uppercase tracking-[0.2em] text-subtle">{blocker.category}</div>
                  </div>
                  <div className="rounded-full border border-current/20 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]">
                    {blocker.severity}
                  </div>
                </div>
                {blocker.remediation && <div className="mt-3 text-sm opacity-80">{blocker.remediation}</div>}
                <div className="mt-3 flex items-center gap-2 text-xs text-subtle">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  {new Date(blocker.detectedAt).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-border bg-surface/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-foreground">Deployment metadata</h3>
              <p className="text-sm text-subtle">Runtime context and deep-links into the supporting operational views.</p>
            </div>
          </div>

          <div className="mt-4 space-y-3 text-sm">
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-subtle">Network</div>
              <div className="mt-1 font-medium text-foreground">{report?.network ?? "—"}</div>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-subtle">Environment</div>
              <div className="mt-1 font-medium text-foreground">{report?.environment ?? "—"}</div>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-subtle">Generated</div>
              <div className="mt-1 font-medium text-foreground">{report ? new Date(report.generatedAt).toLocaleString() : "—"}</div>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-subtle">Snapshot</div>
              <div className="mt-2 space-y-2">
                {sectionRows.map((row) => (
                  <div key={row.title} className="flex items-center justify-between gap-3 rounded-md border border-border bg-white px-3 py-2">
                    <div>
                      <div className="text-sm font-medium text-foreground">{row.title}</div>
                      <div className="text-xs text-subtle">{row.detail}</div>
                    </div>
                    <span className={`rounded-full border px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] ${getSectionTone(row.status as SectionStatus)}`}>
                      {row.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-subtle">Deep links</div>
              <div className="mt-2 flex flex-wrap gap-2">
                <a href="/webhooks" className="inline-flex items-center gap-1 rounded-full border border-border bg-white px-3 py-1.5 text-sm font-medium text-foreground hover:bg-surface">
                  Webhook logs <ChevronRight className="h-3.5 w-3.5" />
                </a>
                <a href="https://stellar.expert/explorer/testnet/txs" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-full border border-border bg-white px-3 py-1.5 text-sm font-medium text-foreground hover:bg-surface">
                  Transactions <ArrowUpRight className="h-3.5 w-3.5" />
                </a>
                <a href="https://stellar.expert/explorer/testnet/contracts" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-full border border-border bg-white px-3 py-1.5 text-sm font-medium text-foreground hover:bg-surface">
                  Registry entries <ArrowUpRight className="h-3.5 w-3.5" />
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
